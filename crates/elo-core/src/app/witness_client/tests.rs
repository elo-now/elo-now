use super::*;
use crate::authority::SpaceGenesis;
use crate::witness::Freshness;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

struct Reply {
    head: RecordId,
    sequence: u64,
    stale: bool,
}

async fn fixture() -> (
    tempfile::TempDir,
    ClientApp,
    Arc<Mutex<Reply>>,
    Arc<AtomicUsize>,
    tokio::task::JoinHandle<()>,
) {
    let temp = tempfile::tempdir().unwrap();
    let mut app = ProfileDraft::new()
        .unwrap()
        .save(
            temp.path().join("profile"),
            "synthetic witness password".into(),
            "General",
        )
        .await
        .unwrap();
    let legacy = app.authorities.0[0].clone();
    let key = ed25519_dalek::SigningKey::from_bytes(&[5; 32]);
    let pin = WitnessPin {
        url: "https://witness.example.test/witness/v1".into(),
        public_key: record::encode_hex(key.verifying_key().as_bytes()),
        key_generation: 1,
    };
    let mut genesis: SpaceGenesis = legacy.genesis().decode().unwrap();
    genesis.v = 4;
    genesis.witness = Some(pin.clone());
    let root = root_key(&genesis.owners[0].root_public_key).unwrap();
    let signed = SignedRecord::sign(
        &serde_json::to_vec(&genesis).unwrap(),
        app.session.signing_key(),
    )
    .unwrap();
    let mut general = Authority::new(
        signed.bytes(),
        signed.id().to_string().parse().unwrap(),
        &root,
        app.session.credential().clone(),
        legacy.stream(),
    )
    .unwrap();
    let mut config = legacy.head().unwrap().clone();
    config.v = 4;
    config.space_id = general.space();
    general
        .apply_config(config.sign(app.session.signing_key()).unwrap())
        .unwrap();
    app.call_host = Some(space_service::SpaceAddress {
        url: "https://unreachable.invalid/spaces".into(),
        scope: team::TeamScope {
            space: general.space(),
            stream: general.stream(),
            root: genesis.owners[0].root_public_key.clone(),
            controller: app.session.credential().id(),
        },
        message_lifetime_seconds: crate::message_retention::MessageRetention::Hours24,
        service_credential: None,
    });
    app.authorities = Authorities(vec![general.clone(), legacy].into());
    app.configure_witness_pin(Some(pin.clone())).unwrap();
    let reply = Arc::new(Mutex::new(Reply {
        head: general.head_id().unwrap(),
        sequence: 2,
        stale: false,
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    app.witness_test_url = Some(format!("http://{}/head", listener.local_addr().unwrap()));
    let hits = Arc::new(AtomicUsize::new(0));
    let count = hits.clone();
    let state = reply.clone();
    let router = axum::Router::new().route(
        "/head",
        axum::routing::post(move |axum::Json(request): axum::Json<HeadRequest>| {
            count.fetch_add(1, Ordering::SeqCst);
            let state = state.lock().unwrap();
            let now = now().unwrap().as_millis() as u64;
            let issued = if state.stale { now - 60_000 } else { now };
            let body = Freshness {
                v: 1,
                kind: "witness.freshness".into(),
                audience: pin.url.clone(),
                nonce: request.nonce,
                space_id: request.space_id,
                stream_id: request.stream_id,
                authority_head: state.head,
                position: Position {
                    sequence: state.sequence,
                    record_id: Some(RecordId::from_bytes([state.sequence as u8; 32])),
                },
                issued_at_ms: issued,
                expires_at_ms: issued + 30_000,
                witness_key_generation: 1,
            };
            let signed = SignedRecord::sign(&serde_json::to_vec(&body).unwrap(), &key).unwrap();
            let response = json!({"freshness":STANDARD.encode(signed.bytes())});
            async move { axum::Json(response) }
        }),
    );
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    (temp, app, reply, hits, server)
}

#[tokio::test]
async fn legacy_hosted_general_reports_protocol_incompatibility_without_downgrading() {
    let (_temp, mut app, _reply, hits, server) = fixture().await;
    let legacy = app.authorities.0[1].clone();
    let address = app.call_host.as_mut().unwrap();
    address.scope.space = legacy.space();
    address.scope.stream = legacy.stream();
    for _ in 0..2 {
        assert_eq!(
            app.require_fresh_membership(&legacy)
                .await
                .unwrap_err()
                .to_string(),
            "This Space uses an unsupported access protocol."
        );
        assert!(
            !app.membership_snapshot()
                .allows(legacy.space(), legacy.stream())
        );
        app.invalidate_permission_leases();
    }
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    server.abort();
    app.close().await.unwrap();
}

#[tokio::test]
async fn hosting_piggyback_cannot_grant_or_renew_witness_or_private_space_access() {
    let (_temp, app, _reply, hits, server) = fixture().await;
    let general = &app.authorities.0[0];
    let private = &app.authorities.0[1];
    let snapshot = app.membership_snapshot();
    let probe = app.membership_probe().unwrap();
    assert_eq!(
        probe.requests.len(),
        1,
        "General v4 must never be checked through hosting"
    );
    app.accept_membership_probe(probe, &json!({"chat_heads":[{"head":private.head_id()}]}))
        .await
        .unwrap();
    assert!(!snapshot.allows(private.space(), private.stream()));
    app.require_fresh_membership(private).await.unwrap();
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    assert!(snapshot.allows(general.space(), general.stream()));
    assert!(snapshot.allows(private.space(), private.stream()));
    for _ in 0..10 {
        app.require_fresh_membership(private).await.unwrap();
    }
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "cache hits never renew a witness lease"
    );
    app.invalidate_permission_leases();
    app.accept_membership_probe(
        app.membership_probe().unwrap(),
        &json!({"chat_heads":[{"head":private.head_id()}]}),
    )
    .await
    .unwrap();
    assert!(!snapshot.allows(general.space(), general.stream()));
    assert!(!snapshot.allows(private.space(), private.stream()));
    server.abort();
    app.close().await.unwrap();
}

#[tokio::test]
async fn signed_expiry_new_head_and_persisted_position_prevent_stale_reauthorization() {
    let (temp, app, reply, _hits, server) = fixture().await;
    let general = app.authorities.0[0].clone();
    app.require_fresh_membership(&general).await.unwrap();
    app.invalidate_permission_leases();
    reply.lock().unwrap().stale = true;
    assert!(app.require_fresh_membership(&general).await.is_err());
    app.invalidate_permission_leases();
    {
        let mut reply = reply.lock().unwrap();
        reply.stale = false;
        reply.sequence = 3;
        reply.head = RecordId::from_bytes([99; 32]);
    }
    assert!(
        app.require_fresh_membership(&general).await.is_err(),
        "a signed changed head requires refresh, including revocation"
    );
    assert_eq!(
        app.witness_floors()
            .unwrap()
            .entries
            .values()
            .next()
            .unwrap()
            .sequence,
        3
    );
    app.invalidate_permission_leases();
    {
        let mut reply = reply.lock().unwrap();
        reply.sequence = 2;
        reply.head = general.head_id().unwrap();
    }
    assert!(app.require_fresh_membership(&general).await.is_err());
    app.close().await.unwrap();
    let reopened = ClientApp::open(
        temp.path().join("profile"),
        "synthetic witness password".into(),
        false,
    )
    .await
    .unwrap();
    assert_eq!(
        reopened
            .witness_floors()
            .unwrap()
            .entries
            .values()
            .next()
            .unwrap()
            .sequence,
        3
    );
    reopened.close().await.unwrap();
    server.abort();
}

#[tokio::test]
async fn v4_without_native_pin_fails_closed_and_pin_changes_discard_leases() {
    let (_temp, mut app, _reply, hits, server) = fixture().await;
    let general = app.authorities.0[0].clone();
    app.require_fresh_membership(&general).await.unwrap();
    let snapshot = app.membership_snapshot();
    app.configure_witness_pin(None).unwrap();
    assert!(!snapshot.allows(general.space(), general.stream()));
    assert!(app.require_fresh_membership(&general).await.is_err());
    assert!(
        app.verify_general_proof(
            &general.call_proof().unwrap(),
            general.space(),
            general.stream()
        )
        .is_err()
    );
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    app.close().await.unwrap();
    server.abort();
}
