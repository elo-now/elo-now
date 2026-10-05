use super::*;
use crate::engine::tests::{AUDIENCE, configured_with_pin};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::SigningKey;
use elo_core::{
    authority::{Authority, Capability, ConfigAction, Member},
    record::SignedRecord,
    vault::Session,
    witness::{Freshness, HeadRequest, Position},
};
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};

struct WitnessFixture {
    key: SigningKey,
    pin: WitnessPin,
    head: Mutex<RecordId>,
    sequence: AtomicU64,
    mode: AtomicU8,
    calls: AtomicU64,
}

impl WitnessFixture {
    fn pin(key: &SigningKey) -> WitnessPin {
        WitnessPin {
            url: "https://witness.example.test/witness/v1".into(),
            public_key: record::encode_hex(key.verifying_key().as_bytes()),
            key_generation: 1,
        }
    }
}

async fn witness_reply(
    State(state): State<Arc<WitnessFixture>>,
    axum::Json(request): axum::Json<HeadRequest>,
) -> Response {
    state.calls.fetch_add(1, Ordering::SeqCst);
    match state.mode.load(Ordering::SeqCst) {
        2 => return (StatusCode::OK, "x".repeat(16_385)).into_response(),
        3 => {
            return (
                StatusCode::TEMPORARY_REDIRECT,
                [(header::LOCATION, "/must-not-follow")],
            )
                .into_response();
        }
        4 => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
        _ => {}
    }
    let now = now_ms();
    let sequence = state.sequence.load(Ordering::SeqCst);
    let body = Freshness {
        v: 1,
        kind: "witness.freshness".into(),
        audience: state.pin.url.clone(),
        nonce: if state.mode.load(Ordering::SeqCst) == 1 {
            "00".repeat(32)
        } else {
            request.nonce
        },
        space_id: request.space_id,
        stream_id: request.stream_id,
        authority_head: *state.head.lock().unwrap(),
        position: Position {
            sequence,
            record_id: Some(RecordId::from_bytes([sequence as u8; 32])),
        },
        issued_at_ms: now,
        expires_at_ms: now + 150,
        witness_key_generation: 1,
    };
    let signed = SignedRecord::sign(&serde_json::to_vec(&body).unwrap(), &state.key).unwrap();
    axum::Json(serde_json::json!({"freshness": STANDARD.encode(signed.bytes())})).into_response()
}

async fn witness_server(
    pin: WitnessPin,
    key: SigningKey,
    head: RecordId,
) -> (Arc<WitnessFixture>, String, tokio::task::JoinHandle<()>) {
    let fixture = Arc::new(WitnessFixture {
        key,
        pin,
        head: Mutex::new(head),
        sequence: AtomicU64::new(1),
        mode: AtomicU8::new(0),
        calls: AtomicU64::new(0),
    });
    let router = Router::new()
        .route("/head", post(witness_reply))
        .with_state(fixture.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/head", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    (fixture, endpoint, task)
}

fn change_members(
    authority: &mut Authority,
    owner: &Session,
    witness: &SigningKey,
    guest: &Session,
    add: bool,
) {
    authority.add_credential(guest.credential().clone());
    let mut config = authority.head().unwrap().clone();
    config.sequence += 1;
    config.previous_config_id = authority.head_id();
    config.nonce = record::random_hex::<16>().unwrap();
    config.witness_evidence = None;
    config.action = ConfigAction {
        operation: if add { "replace" } else { "member.removed" }.into(),
        actor_identity: owner.identity_id(),
        request_record_id: None,
    };
    if add {
        config.members.push(Member {
            identity_id: guest.identity_id(),
            identity_type: "HUMAN".into(),
            root_public_key: guest.credential().record().body()["root_public_key"]
                .as_str()
                .unwrap()
                .into(),
            capabilities: vec![Capability::Read, Capability::Post],
            credential_ids: vec![guest.credential().id()],
            external: false,
        });
    } else {
        config
            .members
            .retain(|member| member.identity_id != guest.identity_id());
    }
    config.members.sort_by_key(|member| member.identity_id);
    let proposal = config.sign(owner.signing_key()).unwrap();
    let committed = authority
        .prepare_witness_owner_config(&proposal, witness)
        .unwrap();
    authority.apply_config(committed).unwrap();
}

fn request(authority: &Authority, user: &Session, operation: Operation) -> Request {
    Request {
        command: STANDARD.encode(
            broker::sign_command(authority, user, AUDIENCE, operation, now())
                .unwrap()
                .bytes(),
        ),
        proof: authority.call_proof().unwrap(),
    }
}

#[tokio::test]
async fn removed_member_cannot_reuse_old_proof_or_upload_and_download_grants_after_lease() {
    let witness_key = SigningKey::from_bytes(&[43; 32]);
    let pin = WitnessFixture::pin(&witness_key);
    let (dir, engine, owner, mut authority) = configured_with_pin(Some(pin.clone()));
    let guest = Session::create().unwrap().0;
    change_members(&mut authority, &owner, &witness_key, &guest, true);
    let (fixture, endpoint, witness_task) = witness_server(
        pin.clone(),
        witness_key.clone(),
        authority.head_id().unwrap(),
    )
    .await;
    let storage = crate::storage::LocalStorage::open(&dir.path().join("objects"))
        .await
        .unwrap();
    let service = Service::new(engine, AUDIENCE.into(), pin.clone())
        .unwrap()
        .with_test_witness_endpoint(pin, endpoint)
        .unwrap()
        .with_test_storage(Arc::new(storage));
    let inspection = service.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(
            listener,
            router(service).into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    let client = reqwest::Client::new();
    let command_url = format!("{url}/storage/v1/command");
    let data = b"ciphertext with independently checked authorization";
    let mut grants = Vec::new();
    for byte in [81, 82] {
        let object_id = AttachmentObjectId::from_bytes([byte; 16]);
        let response = client
            .post(&command_url)
            .json(&request(
                &authority,
                &guest,
                Operation::Reserve {
                    object_id,
                    encrypted_size: data.len() as u64,
                    ciphertext_sha256: record::encode_hex(&Sha256::digest(data)),
                },
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let broker::Response::Transfer { token, .. } = response.json().await.unwrap() else {
            panic!("grant")
        };
        grants.push((object_id, token));
    }
    let completed_url = format!("{url}/storage/v1/objects/{}", grants[0].0);
    assert_eq!(
        client
            .put(&completed_url)
            .bearer_auth(&grants[0].1)
            .body(data.to_vec())
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        client
            .post(&command_url)
            .json(&request(
                &authority,
                &guest,
                Operation::Complete {
                    object_id: grants[0].0
                }
            ))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    let downloaded = client
        .post(&command_url)
        .json(&request(
            &authority,
            &guest,
            Operation::Download {
                object_id: grants[0].0,
            },
        ))
        .send()
        .await
        .unwrap();
    let broker::Response::Transfer {
        token: old_download,
        ..
    } = downloaded.json().await.unwrap()
    else {
        panic!("download grant")
    };
    let former = authority.clone();
    change_members(&mut authority, &owner, &witness_key, &guest, false);
    *fixture.head.lock().unwrap() = authority.head_id().unwrap();
    fixture.sequence.store(2, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(180)).await;
    // A modified client bypassing its UI still signs a fresh request with a valid
    // old membership proof. The independent head comparison must reject it.
    assert_eq!(
        client
            .post(&command_url)
            .json(&request(&former, &guest, Operation::Status))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        client
            .get(&completed_url)
            .bearer_auth(old_download)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        client
            .put(format!("{url}/storage/v1/objects/{}", grants[1].0))
            .bearer_auth(&grants[1].1)
            .body(data.to_vec())
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    // A denial cannot advance the broker's authority chain or consume a token.
    assert!(
        inspection
            .lock()
            .unwrap()
            .token_target(grants[1].0, &grants[1].1, "upload", now())
            .is_ok()
    );
    let response = client
        .post(&command_url)
        .json(&request(
            &authority,
            &owner,
            Operation::Download {
                object_id: grants[0].0,
            },
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let broker::Response::Transfer { token, .. } = response.json().await.unwrap() else {
        panic!("owner grant")
    };
    assert_eq!(
        client
            .get(&completed_url)
            .bearer_auth(token)
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap()
            .as_ref(),
        data
    );
    task.abort();
    witness_task.abort();
}

#[tokio::test]
async fn witness_transport_rejects_nonce_replay_oversize_redirect_and_unavailability() {
    let key = SigningKey::from_bytes(&[44; 32]);
    let pin = WitnessFixture::pin(&key);
    let (_dir, engine, _, authority) = configured_with_pin(Some(pin.clone()));
    engine.pin_witness(&pin).unwrap();
    let engine = Arc::new(Mutex::new(engine));
    let (fixture, endpoint, task) =
        witness_server(pin.clone(), key, authority.head_id().unwrap()).await;
    for mode in [1, 2, 3, 4] {
        fixture.mode.store(mode, Ordering::SeqCst);
        let gate = WitnessGate::new(pin.clone())
            .unwrap()
            .test_endpoint(endpoint.clone());
        assert!(
            gate.require(
                &engine,
                authority.space(),
                authority.stream(),
                authority.head_id().unwrap()
            )
            .await
            .is_err()
        );
    }
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 4);
    assert!(engine.lock().unwrap().witness_position().unwrap().is_none());
    fixture.mode.store(0, Ordering::SeqCst);
    let gate = WitnessGate::new(pin).unwrap().test_endpoint(endpoint);
    let first = gate
        .require(
            &engine,
            authority.space(),
            authority.stream(),
            authority.head_id().unwrap(),
        )
        .await
        .unwrap();
    let cached = gate
        .require(
            &engine,
            authority.space(),
            authority.stream(),
            authority.head_id().unwrap(),
        )
        .await
        .unwrap();
    assert!(Arc::ptr_eq(&first, &cached));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 5);
    tokio::time::sleep(Duration::from_millis(180)).await;
    fixture.mode.store(4, Ordering::SeqCst);
    assert!(
        gate.require(
            &engine,
            authority.space(),
            authority.stream(),
            authority.head_id().unwrap()
        )
        .await
        .is_err()
    );
    task.abort();
}
