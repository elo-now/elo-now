use super::*;
use axum::body::Body;
use ed25519_dalek::{SigningKey, VerifyingKey};
use elo_core::{
    authority::{
        Authority, Capability, ChatKind, ConfigAction, Member, Owner, SpaceGenesis, StreamConfig,
        WitnessPin,
    },
    record,
    vault::Session,
};

const NOW: u64 = 1_800_000_000_000;
const URL: &str = "https://witness.example.test/witness/v1";

fn engine() -> (tempfile::TempDir, Engine) {
    let directory = tempfile::tempdir().unwrap();
    let key = SigningKey::from_bytes(&[91; 32]);
    let path = directory.path().join("key");
    elo_core::vault::write_private(&path, &key.to_bytes(), false).unwrap();
    let pin = WitnessPin {
        url: URL.into(),
        public_key: record::encode_hex(key.verifying_key().as_bytes()),
        key_generation: 1,
    };
    let journal = journal::Journal::open(&directory.path().join("data"), &path, pin, NOW).unwrap();
    (directory, Engine { journal })
}

fn incoming(body: impl Into<Body>) -> HttpRequest {
    HttpRequest::builder()
        .header(header::CONTENT_TYPE, "application/json")
        .body(body.into())
        .unwrap()
}

#[tokio::test]
async fn global_ingest_and_source_rate_reject_before_json_and_release_capacity() {
    let (directory, engine) = engine();
    let service = Service::new(engine, directory.path().join("activation"), false);
    let peer = "127.0.0.1:4444".parse().unwrap();
    let mut permits = Vec::new();
    for _ in 0..INGEST_SLOTS {
        let (_, _, permit) = service
            .receive(peer, incoming("not JSON"), false)
            .await
            .unwrap();
        permits.push(permit);
    }
    // Malformed JSON is deliberately not parsed by admission. A fifth body is
    // rejected by the global bound, even when it comes from a different source.
    assert!(matches!(
        service
            .receive(
                "127.0.0.2:4444".parse().unwrap(),
                incoming("not JSON"),
                false
            )
            .await,
        Err(Error::Limit)
    ));
    drop(permits.pop());
    assert!(service.receive(peer, incoming("{}"), false).await.is_ok());
    drop(permits);
    service
        .rates
        .lock()
        .unwrap()
        .insert(peer.ip(), (Instant::now(), 120));
    assert!(matches!(
        service.receive(peer, incoming("not JSON"), false).await,
        Err(Error::Limit)
    ));
    assert_eq!(service.ingest.available_permits(), INGEST_SLOTS);
}

#[tokio::test]
async fn head_has_small_body_limit_and_global_budget_before_parsing() {
    let (directory, engine) = engine();
    let service = Service::new(engine, directory.path().join("activation"), false);
    let peer = "127.0.0.1:4444".parse().unwrap();
    assert!(matches!(
        service
            .receive(peer, incoming("x".repeat(HEAD_BYTES + 1)), true)
            .await,
        Err(Error::Invalid)
    ));
    assert!(
        service
            .receive(peer, incoming("x".repeat(HEAD_BYTES + 1)), false)
            .await
            .is_ok()
    );
    let mut too_big = incoming("{}");
    too_big.headers_mut().insert(
        header::CONTENT_LENGTH,
        (COMMAND_BYTES + 1).to_string().parse().unwrap(),
    );
    assert!(matches!(
        service.receive(peer, too_big, false).await,
        Err(Error::Invalid)
    ));
    {
        let mut budget = service.head_budget.lock().unwrap();
        budget.start = Instant::now();
        budget.used = 120;
    }
    assert!(matches!(
        service
            .receive(
                "127.0.0.2:4444".parse().unwrap(),
                incoming("not JSON"),
                true
            )
            .await,
        Err(Error::Limit)
    ));
    assert_eq!(service.ingest.available_permits(), INGEST_SLOTS);
}

#[tokio::test]
async fn incomplete_head_body_times_out_and_releases_ingest_slot() {
    use std::io::{Read, Write};
    let (directory, engine) = engine();
    let service = Service::new(engine, directory.path().join("activation"), false);
    let inspection = service.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            router(service).into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    let response = tokio::task::spawn_blocking(move || {
        let mut connection = std::net::TcpStream::connect(address).unwrap();
        connection.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
        connection.write_all(b"POST /witness/v1/head HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 10\r\n\r\n{").unwrap();
        let mut response = [0; 1024];
        let length = connection.read(&mut response).unwrap();
        String::from_utf8_lossy(&response[..length]).to_string()
    }).await.unwrap();
    assert!(response.starts_with("HTTP/1.1 400"));
    assert_eq!(inspection.ingest.available_permits(), INGEST_SLOTS);
    server.abort();
}

fn authority(engine: &Engine) -> (Session, Authority) {
    let owner = Session::create().unwrap().0;
    let root = owner.credential().record().body()["root_public_key"]
        .as_str()
        .unwrap()
        .to_string();
    let root_id: elo_core::ids::IdentityId = root.parse().unwrap();
    let stream = StreamId::from_bytes([83; 16]);
    let genesis = SpaceGenesis {
        v: 4,
        kind: "space.genesis".into(),
        nonce: stream.to_string(),
        issuer_identity: owner.identity_id(),
        owners: vec![Owner {
            identity_id: owner.identity_id(),
            root_public_key: root.clone(),
        }],
        controller_credential_id: owner.credential().id(),
        witness: Some(engine.journal.pin.clone()),
    };
    let signed =
        SignedRecord::sign(&serde_json::to_vec(&genesis).unwrap(), owner.signing_key()).unwrap();
    let mut authority = Authority::new(
        signed.bytes(),
        signed.id().to_string().parse().unwrap(),
        &VerifyingKey::from_bytes(root_id.as_bytes()).unwrap(),
        owner.credential().clone(),
        stream,
    )
    .unwrap();
    let config = StreamConfig {
        v: 4,
        kind: "stream.config".into(),
        nonce: record::random_hex::<16>().unwrap(),
        space_id: authority.space(),
        stream_id: stream,
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
    };
    authority
        .apply_config(config.sign(owner.signing_key()).unwrap())
        .unwrap();
    (owner, authority)
}

fn save_snapshot(engine: &mut Engine, authority: &Authority, request: u8) {
    let key = engine.journal.key.clone();
    let pin = engine.journal.pin.clone();
    let tx = engine.journal.db.transaction().unwrap();
    tx.execute("INSERT INTO spaces(space,stream,proof) VALUES(?1,?2,?3) ON CONFLICT(space) DO UPDATE SET proof=excluded.proof",
        rusqlite::params![authority.space().to_string(), authority.stream().to_string(), serde_json::to_string(&authority.call_proof().unwrap()).unwrap()]).unwrap();
    journal::append(
        &tx,
        &key,
        &pin,
        journal::Event {
            request: RecordId::from_bytes([request; 32]),
            space: authority.space(),
            head: authority.head_id().unwrap(),
            name: "test.snapshot",
            now: NOW,
        },
        crate::wire::Response {
            receipt: None,
            proof: None,
            challenge: None,
        },
    )
    .unwrap();
    tx.commit().unwrap();
}

fn head_request(authority: &Authority) -> HeadRequest {
    HeadRequest {
        space_id: authority.space(),
        stream_id: authority.stream(),
        nonce: record::random_hex::<32>().unwrap(),
    }
}

#[test]
fn cached_head_uses_fresh_nonce_and_invalidates_after_signed_event_or_tampering() {
    let (_directory, mut engine) = engine();
    let (owner, mut authority) = authority(&engine);
    save_snapshot(&mut engine, &authority, 1);
    let startup = engine.journal.startup().unwrap();
    engine
        .journal
        .activate(
            Activation {
                startup_nonce: startup.startup_nonce,
                expected_position: startup.observed_position,
                public_key: startup.public_key,
                key_generation: startup.key_generation,
                expires_at_ms: NOW + 60_000,
            },
            NOW,
        )
        .unwrap();
    let mut cache = HeadCache::new();
    let initial = cache
        .reply(&mut engine, head_request(&authority), NOW)
        .unwrap();
    let request = head_request(&authority);
    let nonce = request.nonce.clone();
    let cached = cache.reply(&mut engine, request, NOW).unwrap();
    let signed = journal::decode(&cached).unwrap();
    signed
        .verify_signature(&engine.journal.pin.key().unwrap())
        .unwrap();
    let fresh: Freshness = signed.decode().unwrap();
    assert_ne!(cached, initial);
    assert_eq!(fresh.nonce, nonce);
    assert_eq!(cache.verifications, 1);
    let old = fresh.authority_head;
    let mut config = authority.head().unwrap().clone();
    config.sequence += 1;
    config.previous_config_id = authority.head_id();
    config.nonce = record::random_hex::<16>().unwrap();
    config.action.operation = "replace".into();
    let proposal = config.sign(owner.signing_key()).unwrap();
    authority
        .apply_config(
            authority
                .prepare_witness_owner_config(&proposal, &engine.journal.key)
                .unwrap(),
        )
        .unwrap();
    save_snapshot(&mut engine, &authority, 2);
    let updated = cache
        .reply(&mut engine, head_request(&authority), NOW)
        .unwrap();
    let updated: Freshness = journal::decode(&updated).unwrap().decode().unwrap();
    assert_ne!(updated.authority_head, old);
    assert_eq!(updated.authority_head, authority.head_id().unwrap());
    assert_eq!(cache.verifications, 2);
    // Leave the signed event ID unchanged and corrupt materialized state. A cache
    // hit must still fail rather than certifying a damaged/rolled-back database.
    engine
        .journal
        .db
        .execute(
            "UPDATE spaces SET proof='{}' WHERE space=?1",
            [authority.space().to_string()],
        )
        .unwrap();
    assert!(matches!(
        cache.reply(&mut engine, head_request(&authority), NOW),
        Err(Error::RecoveryRequired)
    ));
}

#[test]
fn cached_head_cannot_bypass_sealed_startup_or_clock_failure() {
    let (_directory, mut engine) = engine();
    let (_, authority) = authority(&engine);
    let mut cache = HeadCache::new();
    cache.entries.insert(
        (authority.space(), authority.stream()),
        CachedHead {
            event: RecordId::from_bytes([1; 32]),
            head: authority.head_id().unwrap(),
        },
    );
    assert!(matches!(
        cache.reply(&mut engine, head_request(&authority), NOW),
        Err(Error::RecoveryRequired)
    ));
    save_snapshot(&mut engine, &authority, 1);
    let startup = engine.journal.startup().unwrap();
    engine
        .journal
        .activate(
            Activation {
                startup_nonce: startup.startup_nonce,
                expected_position: startup.observed_position,
                public_key: startup.public_key,
                key_generation: startup.key_generation,
                expires_at_ms: NOW + 60_000,
            },
            NOW,
        )
        .unwrap();
    cache
        .reply(&mut engine, head_request(&authority), NOW)
        .unwrap();
    assert!(matches!(
        cache.reply(&mut engine, head_request(&authority), NOW - 1),
        Err(Error::RecoveryRequired)
    ));
    assert!(matches!(
        cache.reply(&mut engine, head_request(&authority), NOW),
        Err(Error::RecoveryRequired)
    ));
}
