use super::*;
use crate::authority::WitnessPin;
use crate::witness::{
    Command, Freshness, HeadRequest, Operation, Position, Receipt, Request, Response,
};
use ed25519_dalek::SigningKey;
use std::sync::{Arc, Mutex};

fn signed<T: Serialize>(body: &T, key: &SigningKey) -> SignedRecord {
    SignedRecord::sign(&serde_json::to_vec(body).unwrap(), key).unwrap()
}

struct Witness {
    authority: Authority,
    position: Position,
    mutations: usize,
    lose_next_ack: bool,
    host_syncs: usize,
}

async fn fixture() -> (tempfile::TempDir, ClientApp, Authority, SigningKey) {
    let temp = tempfile::tempdir().unwrap();
    let mut app = ProfileDraft::new()
        .unwrap()
        .save(
            temp.path().join("profile"),
            "synthetic witnessed pairing password".into(),
            "General",
        )
        .await
        .unwrap();
    app.allow_loopback = true;
    let key = SigningKey::from_bytes(&[91; 32]);
    let pin = WitnessPin {
        url: "https://witness.example.test/witness/v1".into(),
        public_key: record::encode_hex(key.verifying_key().as_bytes()),
        key_generation: 1,
    };
    app.configure_witness_pin(Some(pin.clone())).unwrap();
    let proof = app.owner_general_creation(&"92".repeat(16)).unwrap();
    let genesis = decode_record(&proof.genesis).unwrap();
    let scope = team::TeamScope {
        space: genesis.id().to_string().parse().unwrap(),
        stream: "92".repeat(16).parse().unwrap(),
        controller: app.session.credential().id(),
        root: field(app.session.credential().record().body(), "root_public_key")
            .unwrap()
            .into(),
    };
    let authority = app
        .import_owner_general(&scope, &proof, &[], true)
        .await
        .unwrap();
    assert!(app.require_controller(&authority).is_ok());
    (temp, app, authority, key)
}

async fn server(
    app: &mut ClientApp,
    initial: Authority,
    key: SigningKey,
) -> (Arc<Mutex<Witness>>, tokio::task::JoinHandle<()>) {
    let pin = initial.witness_pin().unwrap().clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    app.witness_test_url = Some(origin.clone());
    app.configure_invitation_host(&format!("{origin}/spaces/v1/create"))
        .unwrap();
    app.call_host = Some(space_service::SpaceAddress {
        url: format!("{origin}/team/v1/spaces"),
        scope: team::TeamScope {
            space: initial.space(),
            stream: initial.stream(),
            controller: initial.initial_controller().id(),
            root: field(
                initial.initial_controller().record().body(),
                "root_public_key",
            )
            .unwrap()
            .into(),
        },
        message_lifetime_seconds: 86_400,
        service_credential: Some(STANDARD.encode(app.session.credential().record().bytes())),
    });
    let state = Arc::new(Mutex::new(Witness {
        authority: initial,
        position: Position {
            sequence: 1,
            record_id: Some(RecordId::from_bytes([93; 32])),
        },
        mutations: 0,
        lose_next_ack: false,
        host_syncs: 0,
    }));
    let commands = state.clone();
    let command_key = key.clone();
    let command_pin = pin.clone();
    let heads = state.clone();
    let hosting = state.clone();
    let host_key = app.session.signing_key().clone();
    let host_credential = STANDARD.encode(app.session.credential().record().bytes());
    let router = axum::Router::new()
        .route("/command", axum::routing::post(move |axum::Json(request): axum::Json<Request>| {
            let mut state = commands.lock().unwrap();
            let record = decode_record(&request.command).unwrap();
            let command: Command = record.decode().unwrap();
            record.verify_signature(state.authority.credential(command.credential_id).unwrap().key()).unwrap();
            crate::calls::require_member(&state.authority, command.credential_id).unwrap();
            let mut status = axum::http::StatusCode::OK;
            let receipt = match command.operation {
                Operation::Read => None,
                Operation::OwnerUpdate { proposal, credentials } => {
                    assert!(state.authority.can_manage(command.credential_id));
                    assert_eq!(Some(command.authority_head), state.authority.head_id());
                    for encoded in credentials {
                        let record = decode_record(&encoded).unwrap();
                        let credential = VerifiedCredential::verify(record.bytes(), &root_key(field(record.body(), "root_public_key").unwrap()).unwrap()).unwrap();
                        state.authority.add_credential(credential);
                    }
                    let proposal = decode_record(&proposal).unwrap();
                    let config = state.authority.prepare_witness_owner_config(&proposal, &command_key).unwrap();
                    state.authority.apply_config(config).unwrap();
                    let receipt = Receipt {
                        v: 1, kind: "witness.receipt".into(), audience: command_pin.url.clone(),
                        sequence: state.position.sequence + 1, previous: state.position.record_id,
                        request_id: record.id(), space_id: command.space_id,
                        authority_head: state.authority.head_id().unwrap(), state_digest: "94".repeat(32),
                        accepted_at_ms: now().unwrap().as_millis() as u64,
                        event: "authority.updated".into(), witness_key_generation: 1,
                    };
                    let receipt = signed(&receipt, &command_key);
                    state.position = Position { sequence: state.position.sequence + 1, record_id: Some(receipt.id()) };
                    state.mutations += 1;
                    if state.lose_next_ack {
                        state.lose_next_ack = false;
                        status = axum::http::StatusCode::SERVICE_UNAVAILABLE;
                    }
                    Some(STANDARD.encode(receipt.bytes()))
                }
                _ => panic!("unexpected witness operation"),
            };
            let response = Response { receipt, proof: Some(state.authority.call_proof().unwrap()), challenge: None };
            async move { (status, axum::Json(response)) }
        }))
        .route("/head", axum::routing::post(move |axum::Json(request): axum::Json<HeadRequest>| {
            let state = heads.lock().unwrap();
            let time = now().unwrap().as_millis() as u64;
            let body = Freshness {
                v: 1, kind: "witness.freshness".into(), audience: pin.url.clone(), nonce: request.nonce,
                space_id: state.authority.space(), stream_id: state.authority.stream(),
                authority_head: state.authority.head_id().unwrap(), position: state.position.clone(),
                issued_at_ms: time, expires_at_ms: time + 30_000, witness_key_generation: 1,
            };
            let response = json!({"freshness":STANDARD.encode(signed(&body, &key).bytes())});
            async move { axum::Json(response) }
        }))
        .route("/team/v1/spaces", axum::routing::post(move |axum::Json(request): axum::Json<space_service::Request>| {
            let mut state = hosting.lock().unwrap();
            let command = decode_record(request.record.as_deref().unwrap()).unwrap();
            command.verify_signature(&host_key.verifying_key()).unwrap();
            let body = match command.body()["action"].as_str().unwrap() {
                "witness_sync" => {
                    let proof: CallAuthorityProof = serde_json::from_value(command.body()["body"]["proof"].clone()).unwrap();
                    let incoming = proof.verify_witnessed(state.authority.space(), state.authority.stream(), state.authority.witness_pin().unwrap()).unwrap();
                    assert_eq!(incoming.head_id(), state.authority.head_id());
                    state.host_syncs += 1;
                    json!({"status":"approved","general_head":incoming.head_id(),"enrollment":{
                        "v":2,"packet":STANDARD.encode(serde_json::to_vec(&Enrollment {proof, contacts: vec![]}).unwrap())
                    }})
                }
                "device_list" => json!({"devices":state.authority.head().unwrap().members[0].credential_ids.iter().map(|id| {
                    json!({"id":id,"credential":STANDARD.encode(state.authority.credential(*id).unwrap().record().bytes())})
                }).collect::<Vec<_>>()}),
                _ => panic!("no legacy authority or revocation command may be used"),
            };
            let answer = json!({"v":1,"kind":"space.response","space":state.authority.space(),"nonce":request.nonce,"body":body,"ciphertext_hash":null});
            let response = space_service::Response {
                record: STANDARD.encode(signed(&answer, &host_key).bytes()), credential: host_credential.clone(), ciphertext: None,
            };
            async move { axum::Json(response) }
        }));
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    (state, task)
}

#[tokio::test]
async fn pairing_reconciles_a_lost_ack_and_revocation_cannot_regrant_the_old_device() {
    let (_temp, mut app, initial, key) = fixture().await;
    let linked = app.session.linked_companion().unwrap();
    let (state, server) = server(&mut app, initial.clone(), key).await;
    state.lock().unwrap().lose_next_ack = true;
    assert!(
        app.authorize_linked_owner_device(linked.credential())
            .await
            .is_err()
    );
    assert_eq!(state.lock().unwrap().mutations, 1);
    app.authorize_linked_owner_device(linked.credential())
        .await
        .unwrap();
    let admitted = app
        .authorities
        .0
        .iter()
        .find(|a| a.space() == initial.space())
        .unwrap();
    assert!(admitted.can_manage(linked.credential().id()));
    assert_eq!(admitted.head().unwrap().members.len(), 1);
    assert_eq!(
        state.lock().unwrap().mutations,
        1,
        "retry must not publish a second grant"
    );
    let credential = STANDARD.encode(linked.credential().record().bytes());
    state.lock().unwrap().lose_next_ack = true;
    let pending = app.revoke_linked_device(&credential).await.unwrap();
    assert_eq!(
        pending["pending"], 1,
        "an uncertain mutation must remain durable"
    );
    assert_eq!(state.lock().unwrap().mutations, 2);
    app.retry_device_revocations(true).await.unwrap();
    assert_eq!(app.linked_devices().await.unwrap()["pending"], 0);
    let revoked = app
        .authorities
        .0
        .iter()
        .find(|a| a.space() == initial.space())
        .unwrap();
    assert!(!revoked.can_manage(linked.credential().id()));
    assert!(crate::calls::require_member(revoked, linked.credential().id()).is_err());
    assert!(
        app.authorize_linked_owner_device(linked.credential())
            .await
            .is_err()
    );
    assert_eq!(state.lock().unwrap().mutations, 2);
    assert_eq!(state.lock().unwrap().host_syncs, 2);
    server.abort();
    app.close().await.unwrap();
}

#[tokio::test]
async fn pairing_requires_the_current_owner_and_the_exact_authorizing_device() {
    let (_temp, app, initial, key) = fixture().await;
    let linked = app.session.linked_companion().unwrap();
    let unrelated = Session::create().unwrap().0.linked_companion().unwrap();
    let wrong_parent = linked.linked_companion().unwrap();
    for target in [
        unrelated.credential(),
        wrong_parent.credential(),
        app.session.credential(),
    ] {
        assert!(
            app.linked_witnessed_owner_proposal(&initial, target)
                .is_err()
        );
    }
    let proposal = app
        .linked_witnessed_owner_proposal(&initial, linked.credential())
        .unwrap()
        .unwrap();
    let mut current = initial.clone();
    current.add_credential(linked.credential().clone());
    let config = current
        .prepare_witness_owner_config(&proposal, &key)
        .unwrap();
    current.apply_config(config).unwrap();
    // The linked owner retires the original device in a later valid witnessed head.
    let mut config = current.head().unwrap().clone();
    config.sequence += 1;
    config.previous_config_id = current.head_id();
    config.nonce = record::random_hex::<16>().unwrap();
    config.controller_credential_id = linked.credential().id();
    config.members[0].credential_ids = vec![linked.credential().id()];
    config.owner_credential_ids = vec![linked.credential().id()];
    config.witness_evidence = None;
    let proposal = config.sign(linked.signing_key()).unwrap();
    let signed = current
        .prepare_witness_owner_config(&proposal, &key)
        .unwrap();
    current.apply_config(signed).unwrap();
    let next = app.session.linked_companion().unwrap();
    assert!(
        app.linked_witnessed_owner_proposal(&current, next.credential())
            .is_err()
    );
    app.close().await.unwrap();
}
