use super::*;
use crate::witness::{Freshness, HeadRequest};
use ed25519_dalek::SigningKey;
use std::sync::{Arc, Mutex};

fn pin(key: &SigningKey) -> WitnessPin {
    WitnessPin {
        url: "https://witness.example.test/witness/v1".into(),
        public_key: record::encode_hex(key.verifying_key().as_bytes()),
        key_generation: 1,
    }
}

fn signed<T: Serialize>(body: &T, key: &SigningKey) -> SignedRecord {
    SignedRecord::sign(&serde_json::to_vec(body).unwrap(), key).unwrap()
}

fn command(pin: &WitnessPin, operation: Operation) -> Command {
    Command {
        v: 1,
        kind: "witness.command".into(),
        nonce: "01".repeat(32),
        audience: pin.url.clone(),
        space_id: SpaceId::from_bytes([2; 32]),
        stream_id: StreamId::from_bytes([3; 16]),
        credential_id: RecordId::from_bytes([4; 32]),
        authority_head: RecordId::from_bytes([5; 32]),
        issued_at_ms: 10_000,
        expires_at_ms: 70_000,
        operation,
    }
}

fn receipt(pin: &WitnessPin, command: &Command, request: &SignedRecord) -> Receipt {
    Receipt {
        v: 1,
        kind: "witness.receipt".into(),
        audience: pin.url.clone(),
        sequence: 2,
        previous: Some(RecordId::from_bytes([6; 32])),
        request_id: request.id(),
        space_id: command.space_id,
        authority_head: command.authority_head,
        state_digest: "07".repeat(32),
        accepted_at_ms: command.issued_at_ms,
        event: "invitation.revoked".into(),
        witness_key_generation: pin.key_generation,
    }
}

#[test]
fn receipt_requires_the_exact_signed_request_scope_event_and_witness() {
    let key = SigningKey::from_bytes(&[8; 32]);
    let pin = pin(&key);
    let command = command(
        &pin,
        Operation::RevokeInvitation {
            policy_id: RecordId::from_bytes([9; 32]),
        },
    );
    let request = signed(&command, &SigningKey::from_bytes(&[10; 32]));
    let body = receipt(&pin, &command, &request);
    let value = serde_json::to_value(&body).unwrap();
    let encoded = STANDARD.encode(signed(&body, &key).bytes());
    assert!(verify_receipt(&pin, &request, &command, &encoded, 10_000, None).is_ok());
    for (field, wrong) in [
        ("kind", json!("witness.freshness")),
        ("audience", json!("https://other.example.test/witness/v1")),
        ("witness_key_generation", json!(2)),
        ("space_id", json!(SpaceId::from_bytes([11; 32]))),
        ("request_id", json!(RecordId::from_bytes([12; 32]))),
        ("authority_head", json!(RecordId::from_bytes([13; 32]))),
        ("event", json!("invitation.registered")),
        ("sequence", json!(0)),
        ("previous", Value::Null),
        ("accepted_at_ms", json!(70_000)),
        ("state_digest", json!("invalid")),
    ] {
        let mut altered = value.clone();
        altered[field] = wrong;
        let altered = STANDARD.encode(signed(&altered, &key).bytes());
        assert!(
            verify_receipt(&pin, &request, &command, &altered, 10_000, None).is_err(),
            "receipt accepted an invalid {field}"
        );
    }
    let wrong_signer = STANDARD.encode(signed(&body, &SigningKey::from_bytes(&[14; 32])).bytes());
    assert!(verify_receipt(&pin, &request, &command, &wrong_signer, 10_000, None).is_err());
    assert!(verify_receipt(&pin, &request, &command, &encoded, 70_000, None).is_err());
}

#[test]
fn receipts_cannot_replay_across_nonces_or_roll_back_the_journal_position() {
    let key = SigningKey::from_bytes(&[8; 32]);
    let owner = SigningKey::from_bytes(&[10; 32]);
    let pin = pin(&key);
    let mut command = command(
        &pin,
        Operation::RevokeInvitation {
            policy_id: RecordId::from_bytes([9; 32]),
        },
    );
    let request = signed(&command, &owner);
    let body = receipt(&pin, &command, &request);
    let encoded = STANDARD.encode(signed(&body, &key).bytes());
    let (_, current) = verify_receipt(&pin, &request, &command, &encoded, 10_000, None).unwrap();
    // The same acknowledgement at the same floor is idempotent.
    assert!(verify_receipt(&pin, &request, &command, &encoded, 10_000, Some(&current)).is_ok());
    for floor in [
        Position {
            sequence: 3,
            record_id: Some(RecordId::from_bytes([15; 32])),
        },
        Position {
            sequence: 2,
            record_id: Some(RecordId::from_bytes([16; 32])),
        },
        Position {
            sequence: 1,
            record_id: Some(RecordId::from_bytes([17; 32])),
        },
    ] {
        assert!(verify_receipt(&pin, &request, &command, &encoded, 10_000, Some(&floor)).is_err());
    }
    let preceding = Position {
        sequence: 1,
        record_id: body.previous,
    };
    assert!(verify_receipt(&pin, &request, &command, &encoded, 10_000, Some(&preceding)).is_ok());
    command.nonce = "ff".repeat(32);
    let next_request = signed(&command, &owner);
    assert!(verify_receipt(&pin, &next_request, &command, &encoded, 10_000, None).is_err());
}

async fn fixture() -> (tempfile::TempDir, ClientApp, Authority, SigningKey) {
    let temp = tempfile::tempdir().unwrap();
    let mut app = ProfileDraft::new()
        .unwrap()
        .save(
            temp.path().join("profile"),
            "synthetic witness command password".into(),
            "General",
        )
        .await
        .unwrap();
    let legacy = app.authorities.0[0].clone();
    let key = SigningKey::from_bytes(&[5; 32]);
    let pin = pin(&key);
    let mut genesis: SpaceGenesis = legacy.genesis().decode().unwrap();
    genesis.v = 4;
    genesis.nonce = legacy.stream().to_string();
    genesis.witness = Some(pin.clone());
    let root = root_key(&genesis.owners[0].root_public_key).unwrap();
    let genesis = signed(&genesis, app.session.signing_key());
    let mut authority = Authority::new(
        genesis.bytes(),
        genesis.id().to_string().parse().unwrap(),
        &root,
        app.session.credential().clone(),
        legacy.stream(),
    )
    .unwrap();
    let mut config = legacy.head().unwrap().clone();
    config.v = 4;
    config.space_id = authority.space();
    authority
        .apply_config(config.sign(app.session.signing_key()).unwrap())
        .unwrap();
    app.authorities = Authorities(vec![authority.clone()].into());
    app.configure_witness_pin(Some(pin)).unwrap();
    (temp, app, authority, key)
}

fn successor(app: &ClientApp, authority: &Authority, key: &SigningKey) -> Authority {
    let mut config = authority.head().unwrap().clone();
    config.sequence += 1;
    config.previous_config_id = authority.head_id();
    config.nonce = record::random_hex::<16>().unwrap();
    config.witness_evidence = None;
    config.action = ConfigAction {
        operation: "replace".into(),
        actor_identity: app.session.credential().identity(),
        request_record_id: None,
    };
    let proposal = config.sign(app.session.signing_key()).unwrap();
    let witnessed = authority
        .prepare_witness_owner_config(&proposal, key)
        .unwrap();
    let mut result = authority.clone();
    result.apply_config(witnessed).unwrap();
    result
}

#[tokio::test]
async fn returned_proof_must_extend_the_local_chain_and_keep_the_configured_pin() {
    let (_temp, app, initial, key) = fixture().await;
    let pin = pin(&key);
    let next = successor(&app, &initial, &key);
    let sibling = successor(&app, &initial, &key);
    assert!(verify_returned_proof(&pin, &initial, &next.call_proof().unwrap()).is_ok());
    assert!(verify_returned_proof(&pin, &next, &initial.call_proof().unwrap()).is_err());
    assert!(verify_returned_proof(&pin, &next, &sibling.call_proof().unwrap()).is_err());
    let wrong_pin = WitnessPin {
        key_generation: 2,
        ..pin
    };
    assert!(verify_returned_proof(&wrong_pin, &initial, &next.call_proof().unwrap()).is_err());
    app.close().await.unwrap();
}

#[tokio::test]
async fn delayed_floor_writes_recheck_persisted_position_and_never_overwrite_newer_state() {
    let (temp, app, _authority, key) = fixture().await;
    let pin = pin(&key);
    assert!(app.witness_position(&pin).unwrap().is_none());
    let current = Position {
        sequence: 4,
        record_id: Some(RecordId::from_bytes([4; 32])),
    };
    app.record_witness_position(&pin, current.clone()).unwrap();
    // Model a response verified with a floor captured before another response wrote.
    for delayed in [
        Position {
            sequence: 3,
            record_id: Some(RecordId::from_bytes([3; 32])),
        },
        Position {
            sequence: 4,
            record_id: Some(RecordId::from_bytes([5; 32])),
        },
    ] {
        assert!(app.record_witness_position(&pin, delayed).is_err());
        assert_eq!(app.witness_position(&pin).unwrap(), Some(current.clone()));
    }
    let next = Position {
        sequence: 5,
        record_id: Some(RecordId::from_bytes([5; 32])),
    };
    assert!(
        app.record_witness_receipt_position(
            &pin,
            next.clone(),
            Some(RecordId::from_bytes([99; 32])),
        )
        .is_err(),
        "a delayed receipt must link to a floor written after its request started"
    );
    assert_eq!(app.witness_position(&pin).unwrap(), Some(current.clone()));
    app.record_witness_receipt_position(&pin, next.clone(), current.record_id)
        .unwrap();
    app.close().await.unwrap();
    let reopened = ClientApp::open(
        temp.path().join("profile"),
        "synthetic witness command password".into(),
        false,
    )
    .await
    .unwrap();
    assert_eq!(reopened.witness_position(&pin).unwrap(), Some(next));
    reopened.close().await.unwrap();
}

#[tokio::test]
async fn registration_sends_owner_signature_bound_work_and_accepts_only_its_receipt() {
    let (_temp, mut app, authority, key) = fixture().await;
    let pin = pin(&key);
    let owner = *app.session.credential().key();
    let expected_head = authority.head_id().unwrap();
    let expected_space = authority.space();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    app.witness_test_url = Some(format!("http://{}", listener.local_addr().unwrap()));
    let router = axum::Router::new().route(
        "/command",
        axum::routing::post(move |axum::Json(request): axum::Json<Request>| {
            request.verify_registration_work().unwrap();
            let signed_request = decode_record(&request.command).unwrap();
            signed_request.verify_signature(&owner).unwrap();
            let command: Command = signed_request.decode().unwrap();
            assert!(matches!(command.operation, Operation::Register));
            assert_eq!(command.space_id, expected_space);
            assert_eq!(command.authority_head, expected_head);
            assert_eq!(request.proof.as_ref().unwrap().configs.len(), 1);
            assert!(request.invitation_signature.is_none());
            let mut body = receipt(&pin, &command, &signed_request);
            body.sequence = 1;
            body.previous = None;
            body.event = "space.registered".into();
            let response = Response {
                receipt: Some(STANDARD.encode(signed(&body, &key).bytes())),
                proof: None,
                challenge: None,
            };
            async move { axum::Json(response) }
        }),
    );
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let receipt = app.witness_register_authority(&authority).await.unwrap();
    assert_eq!(receipt.space_id, expected_space);
    assert_eq!(
        app.witness_position(authority.witness_pin().unwrap())
            .unwrap()
            .unwrap()
            .sequence,
        1
    );
    server.abort();
    app.close().await.unwrap();
}

#[derive(Clone, Copy)]
enum HeadMode {
    Valid,
    WrongNonce,
    NewerHead,
}

#[tokio::test]
async fn read_requires_fresh_nonce_bound_head_before_exposing_a_replayed_proof() {
    let (_temp, mut app, authority, key) = fixture().await;
    let pin = pin(&key);
    let proof = authority.call_proof().unwrap();
    let head = authority.head_id().unwrap();
    let mode = Arc::new(Mutex::new(HeadMode::WrongNonce));
    let state = mode.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    app.witness_test_url = Some(format!("http://{}", listener.local_addr().unwrap()));
    let router = axum::Router::new()
        .route(
            "/command",
            axum::routing::post(move |axum::Json(request): axum::Json<Request>| {
                let command: Command = decode_record(&request.command).unwrap().decode().unwrap();
                assert!(matches!(command.operation, Operation::Read));
                let response = Response {
                    receipt: None,
                    proof: Some(proof.clone()),
                    challenge: None,
                };
                async move { axum::Json(response) }
            }),
        )
        .route(
            "/head",
            axum::routing::post(move |axum::Json(request): axum::Json<HeadRequest>| {
                let mode = *state.lock().unwrap();
                let now_ms = now().unwrap().as_millis() as u64;
                let newer = matches!(mode, HeadMode::NewerHead);
                let body = Freshness {
                    v: 1,
                    kind: "witness.freshness".into(),
                    audience: pin.url.clone(),
                    nonce: if matches!(mode, HeadMode::WrongNonce) {
                        "ff".repeat(32)
                    } else {
                        request.nonce
                    },
                    space_id: request.space_id,
                    stream_id: request.stream_id,
                    authority_head: if newer {
                        RecordId::from_bytes([99; 32])
                    } else {
                        head
                    },
                    position: Position {
                        sequence: if newer { 3 } else { 2 },
                        record_id: Some(RecordId::from_bytes([if newer { 3 } else { 2 }; 32])),
                    },
                    issued_at_ms: now_ms,
                    expires_at_ms: now_ms + 30_000,
                    witness_key_generation: pin.key_generation,
                };
                let response = json!({"freshness":STANDARD.encode(signed(&body, &key).bytes())});
                async move { axum::Json(response) }
            }),
        );
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    assert!(app.witness_read_authority(&authority).await.is_err());
    assert!(
        app.witness_position(authority.witness_pin().unwrap())
            .unwrap()
            .is_none()
    );
    *mode.lock().unwrap() = HeadMode::Valid;
    assert_eq!(
        app.witness_read_authority(&authority)
            .await
            .unwrap()
            .head_id(),
        Some(head)
    );
    *mode.lock().unwrap() = HeadMode::NewerHead;
    assert!(app.witness_read_authority(&authority).await.is_err());
    assert_eq!(
        app.witness_position(authority.witness_pin().unwrap())
            .unwrap()
            .unwrap()
            .sequence,
        3
    );
    *mode.lock().unwrap() = HeadMode::Valid;
    assert!(app.witness_read_authority(&authority).await.is_err());
    server.abort();
    app.close().await.unwrap();
}
