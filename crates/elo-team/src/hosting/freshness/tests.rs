use super::*;
use axum::{Json, Router, http::StatusCode, response::IntoResponse, routing::post};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use elo_core::{
    authority::{Capability, ChatKind, ConfigAction, Member, Owner, SpaceGenesis, StreamConfig},
    record::SignedRecord,
    vault::Session,
    witness::Freshness,
};
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};

fn fixture() -> (Session, WitnessPin, Authority) {
    let (signer, _) = Session::create().unwrap();
    let pin = WitnessPin {
        url: "https://witness.example.test/witness/v1".into(),
        public_key: record::encode_hex(signer.signing_key().verifying_key().as_bytes()),
        key_generation: 1,
    };
    let (owner, recovery) = Session::create().unwrap();
    let root = owner.credential().record().body()["root_public_key"]
        .as_str()
        .unwrap()
        .to_string();
    let genesis = SignedRecord::sign(
        &serde_json::to_vec(&SpaceGenesis {
            v: 4,
            kind: "space.genesis".into(),
            nonce: "ab".repeat(16),
            issuer_identity: owner.identity_id(),
            owners: vec![Owner {
                identity_id: owner.identity_id(),
                root_public_key: root.clone(),
            }],
            controller_credential_id: owner.credential().id(),
            witness: Some(pin.clone()),
        })
        .unwrap(),
        owner.signing_key(),
    )
    .unwrap();
    let mut authority = Authority::new(
        genesis.bytes(),
        genesis.id().to_string().parse().unwrap(),
        &recovery
            .recover_root(owner.identity_id())
            .unwrap()
            .verifying_key(),
        owner.credential().clone(),
        StreamId::from_bytes([0xab; 16]),
    )
    .unwrap();
    authority
        .apply_config(
            StreamConfig {
                v: 4,
                kind: "stream.config".into(),
                nonce: "ab".repeat(16),
                space_id: authority.space(),
                stream_id: authority.stream(),
                sequence: 1,
                previous_config_id: None,
                controller_credential_id: owner.credential().id(),
                members: vec![Member {
                    identity_id: owner.identity_id(),
                    identity_type: "HUMAN".into(),
                    root_public_key: root,
                    capabilities: vec![
                        Capability::Read,
                        Capability::Post,
                        Capability::ShareHistory,
                        Capability::Manage,
                    ],
                    credential_ids: vec![owner.credential().id()],
                    external: false,
                }],
                owner_credential_ids: vec![owner.credential().id()],
                action: ConfigAction {
                    operation: "create".into(),
                    actor_identity: owner.identity_id(),
                    request_record_id: None,
                },
                chat_kind: Some(ChatKind::Chat),
                recovery: None,
                witness_evidence: None,
            }
            .sign(owner.signing_key())
            .unwrap(),
        )
        .unwrap();
    (signer, pin, authority)
}

fn body(pin: &WitnessPin, request: &HeadRequest, head: RecordId, sequence: u64) -> Freshness {
    let now = current().unwrap();
    Freshness {
        v: 1,
        kind: "witness.freshness".into(),
        audience: pin.url.clone(),
        nonce: request.nonce.clone(),
        space_id: request.space_id,
        stream_id: request.stream_id,
        authority_head: head,
        position: Position {
            sequence,
            record_id: Some(RecordId::from_bytes([sequence as u8; 32])),
        },
        issued_at_ms: now,
        expires_at_ms: now + 30_000,
        witness_key_generation: pin.key_generation,
    }
}

fn encode(signer: &Session, body: &Freshness) -> String {
    STANDARD.encode(
        SignedRecord::sign(&serde_json::to_vec(body).unwrap(), signer.signing_key())
            .unwrap()
            .bytes(),
    )
}

fn lease(
    signer: &Session,
    pin: &WitnessPin,
    authority: &Authority,
    sequence: u64,
    fork: bool,
) -> Arc<VerifiedFreshness> {
    let request = HeadRequest {
        space_id: authority.space(),
        stream_id: authority.stream(),
        nonce: record::random_hex::<32>().unwrap(),
    };
    let mut body = body(pin, &request, authority.head_id().unwrap(), sequence);
    if fork {
        body.position.record_id = Some(RecordId::from_bytes([99; 32]));
    }
    Arc::new(
        verify_freshness(
            pin,
            &request,
            &encode(signer, &body),
            Instant::now(),
            current().unwrap(),
            None,
        )
        .unwrap(),
    )
}

#[test]
fn restart_preserves_global_floor_and_pin_but_discards_leases() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("freshness");
    let (signer, pin, authority) = fixture();
    let gate = WitnessGate::open(&path, pin.clone()).unwrap();
    let current_lease = lease(&signer, &pin, &authority, 5, false);
    gate.observe(current_lease.clone()).unwrap();
    gate.check(&authority, &current_lease).unwrap();
    assert!(WitnessGate::open(&path, pin.clone()).is_err());
    drop(gate);
    let mut changed = pin.clone();
    changed.key_generation += 1;
    assert!(WitnessGate::open(&path, changed).is_err());
    let gate = WitnessGate::open(&path, pin.clone()).unwrap();
    assert!(gate.state.lock().unwrap().cache.is_empty());
    assert!(
        gate.observe(lease(&signer, &pin, &authority, 4, false))
            .is_err()
    );
    assert!(
        gate.observe(lease(&signer, &pin, &authority, 5, true))
            .is_err()
    );
    gate.observe(lease(&signer, &pin, &authority, 6, false))
        .unwrap();
    assert!(gate.check(&authority, &current_lease).is_err());
    let (_, _, foreign_authority) = fixture();
    assert!(gate.check(&foreign_authority, &current_lease).is_err());
    drop(gate);
    std::fs::remove_file(path.join("floor.json")).unwrap();
    assert!(WitnessGate::open(&path, pin).is_err());
}

#[tokio::test]
async fn concurrent_response_cannot_lower_the_floor_or_replace_a_fork() {
    let directory = tempfile::tempdir().unwrap();
    let (signer, pin, authority) = fixture();
    let gate = WitnessGate::open(&directory.path().join("freshness"), pin.clone()).unwrap();
    // Both responses are valid in isolation, as if requested before either arrived.
    let earlier = lease(&signer, &pin, &authority, 9, false);
    let later = lease(&signer, &pin, &authority, 10, false);
    gate.observe(later.clone()).unwrap();
    assert!(gate.observe(earlier).is_err());
    assert!(
        gate.observe(lease(&signer, &pin, &authority, 10, true))
            .is_err()
    );
    assert_eq!(
        gate.state.lock().unwrap().floor.position,
        Some(later.body().position.clone())
    );
    // A failed durable write must not publish the newer lease in memory.
    std::fs::remove_file(&gate.path).unwrap();
    std::fs::create_dir(&gate.path).unwrap();
    assert!(
        gate.observe(lease(&signer, &pin, &authority, 11, false))
            .is_err()
    );
    assert_eq!(
        gate.state.lock().unwrap().floor.position,
        Some(later.body().position.clone())
    );
    assert!(gate.state.lock().unwrap().cache.is_empty());
    assert!(gate.check(&authority, &later).is_err());
    assert!(gate.require(&authority).await.is_err());
}

#[tokio::test]
async fn http_gate_rejects_sealed_replay_wrong_head_oversize_and_redirect() {
    let directory = tempfile::tempdir().unwrap();
    let (signer, pin, authority) = fixture();
    let expected_head = authority.head_id().unwrap();
    let mode = Arc::new(AtomicUsize::new(0));
    let count = Arc::new(AtomicUsize::new(0));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/head", listener.local_addr().unwrap());
    let app = Router::new().route(
        "/head",
        post({
            let mode = mode.clone();
            let count = count.clone();
            let pin = pin.clone();
            let signer = Arc::new(signer);
            move |Json(request): Json<HeadRequest>| {
                let mode = mode.load(Ordering::SeqCst);
                let pin = pin.clone();
                let signer = signer.clone();
                count.fetch_add(1, Ordering::SeqCst);
                async move {
                    if mode == 1 {
                        return StatusCode::SERVICE_UNAVAILABLE.into_response();
                    }
                    if mode == 2 {
                        return axum::response::Redirect::temporary("/head").into_response();
                    }
                    if mode == 3 {
                        return "x".repeat(RESPONSE_LIMIT + 1).into_response();
                    }
                    let mut value = body(&pin, &request, expected_head, 5);
                    match mode {
                        4 => value.nonce = "22".repeat(32),
                        5 => value.authority_head = RecordId::from_bytes([99; 32]),
                        6 => {
                            value.issued_at_ms -= 31_000;
                            value.expires_at_ms -= 31_000;
                        }
                        7 => value.space_id = SpaceId::from_bytes([99; 32]),
                        8 => value.witness_key_generation += 1,
                        _ => {}
                    }
                    Json(json!({"freshness":encode(&signer, &value)})).into_response()
                }
            }
        }),
    );
    let server = tokio::spawn(axum::serve(listener, app).into_future());
    let mut gate = WitnessGate::open(&directory.path().join("freshness"), pin).unwrap();
    // Test transport override is private to this module; production pins require HTTPS.
    gate.endpoint = endpoint;
    for failed in 1..=8 {
        mode.store(failed, Ordering::SeqCst);
        assert!(
            gate.require(&authority).await.is_err(),
            "accepted mode {failed}"
        );
    }
    mode.store(0, Ordering::SeqCst);
    let first = gate.require(&authority).await.unwrap();
    let second = gate.require(&authority).await.unwrap();
    assert!(Arc::ptr_eq(&first, &second));
    assert_eq!(count.load(Ordering::SeqCst), 9);
    gate.check(&authority, &second).unwrap();
    assert!(!second.is_valid(second.body().expires_at_ms));
    server.abort();
}

#[tokio::test]
async fn creation_rechecks_the_lease_after_waiting_before_publication() {
    use super::super::{Host, HostConfig, reservation_id, space_host::CreateCommand};
    let directory = tempfile::tempdir().unwrap();
    let (signer, pin, authority) = fixture();
    let config = HostConfig {
        root: directory.path().join("host"),
        public_url: "https://host.example.test".into(),
        max_spaces_per_identity: 3,
        max_spaces: 128,
        max_space_creations_per_day: 32,
        mailbox_quota_bytes: 150_000_000,
        operator_snapshot: None,
        backup_access_key: None,
        call_admission_key: None,
        attachment_storage: None,
        recovery_recipient: None,
        client_policy: Default::default(),
        witness: Some(pin.clone()),
    };
    let host = Host::open(config.clone(), false).await.unwrap();
    let command = CreateCommand {
        v: 2,
        kind: "space.create".into(),
        host: format!("{}/spaces/v1/create", config.public_url),
        request_id: "ab".repeat(16),
        issued: current().unwrap(),
        name: "Witness test".into(),
        contact_email: "owner@example.test".into(),
        message_lifetime_seconds: 86400,
        require_approval: false,
        authority: Some(authority.call_proof().unwrap()),
    };
    let creator = authority.initial_controller().identity();
    assert!(
        host.provision_from_network_inner(&command, creator, None, None, None)
            .await
            .is_err()
    );
    assert_eq!(
        std::fs::read_dir(config.root.join("spaces"))
            .unwrap()
            .count(),
        0
    );
    let first = lease(&signer, &pin, &authority, 5, false);
    host.witness
        .as_ref()
        .unwrap()
        .observe(first.clone())
        .unwrap();
    let space_path = config
        .root
        .join("spaces")
        .join(reservation_id(creator, &command.request_id));
    let held = host.spaces.write().await;
    let worker_host = host.clone();
    let worker_authority = command
        .authority
        .as_ref()
        .unwrap()
        .verify_witnessed(authority.space(), authority.stream(), &pin)
        .unwrap();
    let work = tokio::spawn(async move {
        worker_host
            .provision_from_network_inner(
                &command,
                creator,
                None,
                None,
                Some((&worker_authority, &first)),
            )
            .await
            .is_err()
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        while !space_path.join("reservation.json").exists() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    host.witness
        .as_ref()
        .unwrap()
        .observe(lease(&signer, &pin, &authority, 6, false))
        .unwrap();
    drop(held);
    assert!(work.await.unwrap());
    assert!(host.spaces.read().await.is_empty());
    assert!(!space_path.join("config.json").exists());
    drop(host);
    let mut unpinned = config;
    unpinned.witness = None;
    assert!(Host::open(unpinned, false).await.is_err());
}
