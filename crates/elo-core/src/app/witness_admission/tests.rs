use super::*;
use crate::{
    authority::WitnessInvitationPolicy,
    identity::DeviceCredential,
    witness::{
        Freshness, HeadRequest,
        link::{self, Descriptor, InvitationSeed},
    },
};
use ed25519_dalek::SigningKey;
use std::sync::{Arc, Mutex};

fn signed<T: Serialize>(value: &T, key: &SigningKey) -> SignedRecord {
    SignedRecord::sign(&serde_json::to_vec(value).unwrap(), key).unwrap()
}
fn encode(value: &SignedRecord) -> String {
    STANDARD.encode(value.bytes())
}
fn time() -> u64 {
    now().unwrap().as_millis() as u64
}

fn owner_successor(
    authority: &Authority,
    owner: &SigningKey,
    witness: &SigningKey,
) -> SignedRecord {
    let mut config = authority.head().unwrap().clone();
    config.sequence += 1;
    config.previous_config_id = authority.head_id();
    config.nonce = record::random_hex::<16>().unwrap();
    config.witness_evidence = None;
    config.action = ConfigAction {
        operation: "replace".into(),
        actor_identity: authority.initial_controller().identity(),
        request_record_id: None,
    };
    authority
        .prepare_witness_owner_config(&config.sign(owner).unwrap(), witness)
        .unwrap()
}

struct Mock {
    authority: Authority,
    owner: SigningKey,
    witness: SigningKey,
    invitation: VerifyingKey,
    pin: WitnessPin,
    sequence: u64,
    tip: Option<RecordId>,
    replies: BTreeMap<RecordId, Response>,
    commands: Vec<(String, RecordId)>,
    wire: Vec<Vec<u8>>,
    mode: &'static str,
}

impl Mock {
    fn command(
        &mut self,
        request: Request,
    ) -> std::result::Result<Response, axum::http::StatusCode> {
        use axum::http::StatusCode;
        self.wire.push(serde_json::to_vec(&request).unwrap());
        assert!(request.proof.is_none() && request.registration_work.is_none());
        let record = decode_record(&request.command).unwrap();
        let command: Command = record.decode().unwrap();
        assert_eq!(command.audience, self.pin.url);
        assert_eq!(command.space_id, self.authority.space());
        assert_eq!(command.stream_id, self.authority.stream());
        let candidate = match &command.operation {
            Operation::Challenge { credential, .. } | Operation::Admit { credential, .. } => {
                let credential = decode_record(credential).unwrap();
                let root =
                    root_key(credential.body()["root_public_key"].as_str().unwrap()).unwrap();
                VerifiedCredential::verify(credential.bytes(), &root).unwrap()
            }
            Operation::Read => self
                .authority
                .credential(command.credential_id)
                .unwrap()
                .clone(),
            _ => panic!("unexpected candidate command"),
        };
        assert_eq!(candidate.id(), command.credential_id);
        record.verify_signature(candidate.key()).unwrap();
        let event = match command.operation {
            Operation::Challenge { .. } => "invitation.challenged",
            Operation::Admit { .. } => "device.admitted",
            Operation::Read => "read",
            _ => unreachable!(),
        };
        self.commands.push((event.into(), record.id()));
        if self.mode == "forbidden" {
            return Err(StatusCode::FORBIDDEN);
        }
        if let Some(reply) = self.replies.get(&record.id()) {
            return Ok(reply.clone());
        }
        let mut response = Response {
            receipt: None,
            proof: None,
            challenge: None,
        };
        let accepted = time();
        match command.operation {
            Operation::Challenge {
                policy_id,
                client_nonce,
                ..
            } => {
                let possession =
                    decode_record(request.invitation_signature.as_deref().unwrap()).unwrap();
                assert_eq!(possession.body_bytes(), record.body_bytes());
                possession.verify_signature(&self.invitation).unwrap();
                let body = WitnessChallenge {
                    v: 1,
                    kind: "witness.challenge".into(),
                    nonce: record::random_hex::<32>().unwrap(),
                    client_nonce,
                    space_id: command.space_id,
                    stream_id: command.stream_id,
                    policy_id,
                    credential_id: command.credential_id,
                    issued_at_ms: accepted,
                    expires_at_ms: accepted + 120_000,
                    witness_key_generation: self.pin.key_generation,
                };
                response.challenge = Some(encode(&signed(&body, &self.witness)));
            }
            Operation::Admit { mut evidence, .. } => {
                assert!(request.invitation_signature.is_none());
                let device = decode_record(&evidence.device_intent).unwrap();
                let possession = decode_record(&evidence.invitation_intent).unwrap();
                assert_eq!(device.body_bytes(), possession.body_bytes());
                device.verify_signature(candidate.key()).unwrap();
                possession.verify_signature(&self.invitation).unwrap();
                self.authority.add_credential(candidate);
                evidence.admitted_at_ms = accepted;
                let next = self
                    .authority
                    .prepare_witness_admission(evidence, &self.witness)
                    .unwrap();
                self.authority.apply_config(next).unwrap();
            }
            Operation::Read => {
                if self.mode == "read_unavailable_once" {
                    self.mode = "normal";
                    return Err(StatusCode::SERVICE_UNAVAILABLE);
                }
                if self.mode == "removed" {
                    let mut config = self.authority.head().unwrap().clone();
                    config.sequence += 1;
                    config.previous_config_id = self.authority.head_id();
                    config.nonce = record::random_hex::<16>().unwrap();
                    config.witness_evidence = None;
                    config
                        .members
                        .retain(|member| !member.credential_ids.contains(&command.credential_id));
                    let next = self
                        .authority
                        .prepare_witness_owner_config(
                            &config.sign(&self.owner).unwrap(),
                            &self.witness,
                        )
                        .unwrap();
                    self.authority.apply_config(next).unwrap();
                }
                response.proof = Some(self.authority.call_proof().unwrap());
                return Ok(response);
            }
            _ => unreachable!(),
        }
        self.sequence += 1;
        let body = Receipt {
            v: 1,
            kind: "witness.receipt".into(),
            audience: self.pin.url.clone(),
            sequence: self.sequence,
            previous: self.tip,
            request_id: record.id(),
            space_id: command.space_id,
            authority_head: self.authority.head_id().unwrap(),
            state_digest: "11".repeat(32),
            accepted_at_ms: accepted,
            event: event.into(),
            witness_key_generation: self.pin.key_generation,
        };
        let receipt = signed(&body, &self.witness);
        self.tip = Some(receipt.id());
        response.receipt = Some(encode(&receipt));
        self.replies.insert(record.id(), response.clone());
        Ok(response)
    }

    fn head(&mut self, request: HeadRequest) -> Value {
        let now = time();
        if self.mode == "advance_head_once" {
            let next = owner_successor(&self.authority, &self.owner, &self.witness);
            self.authority.apply_config(next).unwrap();
            self.sequence += 1;
            let receipt = signed(
                &Receipt {
                    v: 1,
                    kind: "witness.receipt".into(),
                    audience: self.pin.url.clone(),
                    sequence: self.sequence,
                    previous: self.tip,
                    request_id: RecordId::from_bytes([87; 32]),
                    space_id: self.authority.space(),
                    authority_head: self.authority.head_id().unwrap(),
                    state_digest: "88".repeat(32),
                    accepted_at_ms: now,
                    event: "authority.updated".into(),
                    witness_key_generation: self.pin.key_generation,
                },
                &self.witness,
            );
            self.tip = Some(receipt.id());
            self.mode = "normal";
        }
        let body = Freshness {
            v: 1,
            kind: "witness.freshness".into(),
            audience: self.pin.url.clone(),
            nonce: if self.mode == "wrong_fresh_nonce" {
                "99".repeat(32)
            } else {
                request.nonce
            },
            space_id: request.space_id,
            stream_id: request.stream_id,
            authority_head: self.authority.head_id().unwrap(),
            position: Position {
                sequence: self.sequence,
                record_id: self.tip,
            },
            issued_at_ms: now,
            expires_at_ms: now + 30_000,
            witness_key_generation: self.pin.key_generation,
        };
        json!({"freshness":encode(&signed(&body, &self.witness))})
    }
}

struct Running(tokio::task::JoinHandle<()>);
impl Drop for Running {
    fn drop(&mut self) {
        self.0.abort();
    }
}
struct Fixture {
    _temp: tempfile::TempDir,
    _running: Running,
    app: ClientApp,
    invitation: VerifiedDescriptor,
    seed: Vec<u8>,
    state: Arc<Mutex<Mock>>,
    admit_committed: Arc<tokio::sync::Notify>,
    release_admit: Arc<tokio::sync::Notify>,
}

async fn fixture(approval: bool) -> Fixture {
    let temp = tempfile::tempdir().unwrap();
    let mut app = ProfileDraft::new()
        .unwrap()
        .save(
            temp.path().join("candidate"),
            "synthetic candidate password".into(),
            "Guest",
        )
        .await
        .unwrap();
    let owner = SigningKey::from_bytes(&[1; 32]);
    let root = SigningKey::from_bytes(&[2; 32]);
    let age = age::x25519::Identity::generate();
    let credential =
        DeviceCredential::issue(&root, &owner.verifying_key(), &age.to_public()).unwrap();
    let witness = SigningKey::from_bytes(&[3; 32]);
    let pin = WitnessPin {
        url: "https://witness.example.test/witness/v1".into(),
        public_key: record::encode_hex(witness.verifying_key().as_bytes()),
        key_generation: 1,
    };
    let stream = StreamId::from_bytes([4; 16]);
    let genesis = signed(
        &SpaceGenesis {
            v: 4,
            kind: "space.genesis".into(),
            nonce: stream.to_string(),
            issuer_identity: credential.identity(),
            owners: vec![Owner {
                identity_id: credential.identity(),
                root_public_key: record::encode_hex(root.verifying_key().as_bytes()),
            }],
            controller_credential_id: credential.id(),
            witness: Some(pin.clone()),
        },
        &owner,
    );
    let mut authority = Authority::new(
        genesis.bytes(),
        genesis.id().to_string().parse().unwrap(),
        &root.verifying_key(),
        credential.clone(),
        stream,
    )
    .unwrap();
    let config = StreamConfig {
        v: 4,
        kind: "stream.config".into(),
        nonce: stream.to_string(),
        space_id: authority.space(),
        stream_id: stream,
        sequence: 1,
        previous_config_id: None,
        controller_credential_id: credential.id(),
        members: vec![Member {
            identity_id: credential.identity(),
            identity_type: "HUMAN".into(),
            root_public_key: record::encode_hex(root.verifying_key().as_bytes()),
            capabilities: vec![
                Capability::Read,
                Capability::Post,
                Capability::ShareHistory,
                Capability::Manage,
            ],
            credential_ids: vec![credential.id()],
            external: false,
        }],
        owner_credential_ids: vec![credential.id()],
        action: ConfigAction {
            operation: "create".into(),
            actor_identity: credential.identity(),
            request_record_id: None,
        },
        chat_kind: Some(ChatKind::Chat),
        recovery: None,
        witness_evidence: None,
    };
    authority
        .apply_config(config.sign(&owner).unwrap())
        .unwrap();
    let seed = InvitationSeed::generate().unwrap();
    let invitation_key = seed.invitation_public_key().unwrap();
    let policy = signed(
        &WitnessInvitationPolicy {
            v: 1,
            kind: "witness.invitation".into(),
            nonce: record::random_hex::<16>().unwrap(),
            space_id: authority.space(),
            stream_id: stream,
            authority_head: authority.head_id().unwrap(),
            issuer_credential_id: credential.id(),
            invitation_public_key: record::encode_hex(invitation_key.as_bytes()),
            not_before_ms: time() - 1_000,
            expires_at_ms: time() + 3_600_000,
            require_approval: approval,
            max_uses: 5,
            witness_key_generation: 1,
        },
        &owner,
    );
    let descriptor = Descriptor {
        v: 1,
        kind: "witness.invitation.descriptor".into(),
        hosting_profile: None,
        name: "Test Space".into(),
        address: space_service::SpaceAddress {
            url: format!(
                "https://api.example.test/spaces/{}/team/v1/spaces",
                authority.space()
            ),
            scope: team::TeamScope {
                space: authority.space(),
                stream,
                root: record::encode_hex(root.verifying_key().as_bytes()),
                controller: credential.id(),
            },
            message_lifetime_seconds: crate::message_retention::MessageRetention::Hours6,
            service_credential: None,
        },
        witness: pin.clone(),
        proof: authority.call_proof().unwrap(),
        policy: encode(&policy),
        invitation_public_key: record::encode_hex(invitation_key.as_bytes()),
    };
    let sealed = link::seal(
        &descriptor,
        &owner,
        seed,
        "https://api.example.test",
        &pin,
        time(),
    )
    .unwrap();
    let url = sealed.link.to_url();
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&url[link::PREFIX.len()..])
        .unwrap();
    let invitation = sealed
        .link
        .open(&sealed.ciphertext, "https://api.example.test", &pin, time())
        .unwrap();
    app.configure_witness_pin(Some(pin.clone())).unwrap();
    let state = Arc::new(Mutex::new(Mock {
        authority,
        owner,
        witness,
        invitation: invitation_key,
        pin,
        sequence: 2,
        tip: Some(RecordId::from_bytes([5; 32])),
        replies: BTreeMap::new(),
        commands: vec![],
        wire: vec![],
        mode: "normal",
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    app.witness_test_url = Some(format!("http://{}", listener.local_addr().unwrap()));
    let commands = state.clone();
    let heads = state.clone();
    let admit_committed = Arc::new(tokio::sync::Notify::new());
    let release_admit = Arc::new(tokio::sync::Notify::new());
    let committed = admit_committed.clone();
    let release = release_admit.clone();
    let router = axum::Router::new()
        .route(
            "/command",
            axum::routing::post(move |axum::Json(request): axum::Json<Request>| async move {
                let (reply, pause) = {
                    let mut state = commands.lock().unwrap();
                    let reply = state.command(request);
                    let pause = state.mode == "pause_ack"
                        && state
                            .commands
                            .last()
                            .is_some_and(|command| command.0 == "device.admitted");
                    (reply, pause)
                };
                if pause {
                    committed.notify_one();
                    release.notified().await;
                }
                reply.map(axum::Json)
            }),
        )
        .route(
            "/head",
            axum::routing::post(
                move |axum::Json(request): axum::Json<HeadRequest>| async move {
                    axum::Json(heads.lock().unwrap().head(request))
                },
            ),
        );
    let running = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    Fixture {
        _temp: temp,
        _running: Running(running),
        app,
        invitation,
        seed: raw[33..].to_vec(),
        state,
        admit_committed,
        release_admit,
    }
}

#[tokio::test]
async fn admission_uses_both_signatures_and_requires_full_proof_and_fresh_head() {
    let f = fixture(false).await;
    let mut pending = f
        .app
        .witness_prepare_admission(&f.invitation, "Guest")
        .await
        .unwrap();
    assert!(!pending.requires_approval());
    let WitnessAdmissionOutcome::Admitted(authority) =
        f.app.witness_admit(&mut pending, None).await.unwrap()
    else {
        panic!("unexpected approval requirement")
    };
    assert!(crate::calls::require_member(&authority, f.app.session.credential().id()).is_ok());
    assert!(!authority.can_manage(f.app.session.credential().id()));
    {
        let state = f.state.lock().unwrap();
        assert_eq!(
            state
                .commands
                .iter()
                .map(|x| x.0.as_str())
                .collect::<Vec<_>>(),
            ["invitation.challenged", "device.admitted", "read"]
        );
        assert_eq!(
            f.app
                .witness_position(&state.pin)
                .unwrap()
                .unwrap()
                .sequence,
            state.sequence
        );
        assert!(
            state
                .wire
                .iter()
                .all(|wire| !wire.windows(32).any(|part| part == f.seed))
        );
        assert!(
            state
                .wire
                .iter()
                .all(|wire| !String::from_utf8_lossy(wire).contains("seed"))
        );
    }
    f.app.close().await.unwrap();
}

#[tokio::test]
async fn approval_required_is_explicit_and_never_inferred_from_forbidden() {
    let f = fixture(true).await;
    let mut pending = f
        .app
        .witness_prepare_admission(&f.invitation, "Guest")
        .await
        .unwrap();
    assert!(matches!(
        f.app.witness_admit(&mut pending, None).await.unwrap(),
        WitnessAdmissionOutcome::ApprovalRequired
    ));
    assert_eq!(f.state.lock().unwrap().commands.len(), 1);
    let approval = {
        let state = f.state.lock().unwrap();
        signed(
            &WitnessApproval {
                v: 1,
                kind: "witness.approval".into(),
                nonce: record::random_hex::<16>().unwrap(),
                space_id: state.authority.space(),
                stream_id: state.authority.stream(),
                authority_head: state.authority.head_id().unwrap(),
                issuer_credential_id: state.authority.initial_controller().id(),
                intent_id: decode_record(&pending.approval_request().device_intent)
                    .unwrap()
                    .id(),
                readmission: false,
            },
            &state.owner,
        )
    };
    assert!(matches!(
        f.app
            .witness_admit(&mut pending, Some(&approval))
            .await
            .unwrap(),
        WitnessAdmissionOutcome::Admitted(_)
    ));
    f.app.close().await.unwrap();
    let f = fixture(false).await;
    let mut pending = f
        .app
        .witness_prepare_admission(&f.invitation, "Guest")
        .await
        .unwrap();
    f.state.lock().unwrap().mode = "forbidden";
    assert!(f.app.witness_admit(&mut pending, None).await.is_err());
    f.app.close().await.unwrap();
}

#[tokio::test]
async fn missing_or_changed_native_pin_and_expired_pending_stop_before_network() {
    let mut f = fixture(false).await;
    f.app.configure_witness_pin(None).unwrap();
    assert!(
        f.app
            .witness_prepare_admission(&f.invitation, "Guest")
            .await
            .is_err()
    );
    assert!(f.state.lock().unwrap().commands.is_empty());
    f.app
        .configure_witness_pin(Some(f.state.lock().unwrap().pin.clone()))
        .unwrap();
    let mut pending = f
        .app
        .witness_prepare_admission(&f.invitation, "Guest")
        .await
        .unwrap();
    pending.started = Instant::now() - Duration::from_secs(121);
    assert!(f.app.witness_admit(&mut pending, None).await.is_err());
    pending.started = Instant::now();
    let mut pin = f.state.lock().unwrap().pin.clone();
    pin.key_generation += 1;
    f.app.configure_witness_pin(Some(pin)).unwrap();
    assert!(f.app.witness_admit(&mut pending, None).await.is_err());
    assert_eq!(f.state.lock().unwrap().commands.len(), 1);
    f.app.close().await.unwrap();
}

#[tokio::test]
async fn failed_proof_read_retries_only_reads_after_the_admission_acknowledgement() {
    let f = fixture(false).await;
    let mut pending = f
        .app
        .witness_prepare_admission(&f.invitation, "Guest")
        .await
        .unwrap();
    f.state.lock().unwrap().mode = "read_unavailable_once";
    assert!(f.app.witness_admit(&mut pending, None).await.is_err());
    assert!(matches!(
        f.app.witness_admit(&mut pending, None).await.unwrap(),
        WitnessAdmissionOutcome::Admitted(_)
    ));
    {
        let state = f.state.lock().unwrap();
        let requests = state
            .commands
            .iter()
            .filter(|x| x.0 == "device.admitted")
            .map(|x| x.1)
            .collect::<Vec<_>>();
        assert_eq!(requests.len(), 1);
        assert_eq!(state.authority.head().unwrap().sequence, 2);
    }
    f.app.close().await.unwrap();
}

#[tokio::test]
async fn removed_credential_or_replayed_freshness_never_reports_admission_success() {
    for mode in ["removed", "wrong_fresh_nonce"] {
        let f = fixture(false).await;
        let mut pending = f
            .app
            .witness_prepare_admission(&f.invitation, "Guest")
            .await
            .unwrap();
        f.state.lock().unwrap().mode = mode;
        assert!(
            f.app.witness_admit(&mut pending, None).await.is_err(),
            "accepted {mode}"
        );
        f.app.close().await.unwrap();
    }
}

#[tokio::test]
async fn signed_challenge_cannot_change_device_scope_policy_nonce_or_deadline() {
    let f = fixture(false).await;
    let pending = f
        .app
        .witness_prepare_admission(&f.invitation, "Guest")
        .await
        .unwrap();
    {
        let state = f.state.lock().unwrap();
        let request: Request = serde_json::from_slice(&state.wire[0]).unwrap();
        let command: Command = decode_record(&request.command).unwrap().decode().unwrap();
        let original = decode_record(&pending.evidence.challenge).unwrap();
        for (field, value) in [
            ("client_nonce", json!("22".repeat(32))),
            ("nonce", json!("bad")),
            ("space_id", json!(SpaceId::from_bytes([22; 32]))),
            ("stream_id", json!(StreamId::from_bytes([22; 16]))),
            ("policy_id", json!(RecordId::from_bytes([22; 32]))),
            ("credential_id", json!(RecordId::from_bytes([22; 32]))),
            ("witness_key_generation", json!(2)),
            ("expires_at_ms", json!(time() - 1)),
            ("issued_at_ms", json!(time() + 60_000)),
        ] {
            let mut body = original.body().clone();
            body[field] = value;
            let altered = encode(&signed(&body, &state.witness));
            assert!(
                verify_challenge(&state.pin, &command, &altered, time()).is_err(),
                "accepted {field}"
            );
        }
    }
    f.app.close().await.unwrap();
}

#[tokio::test]
async fn acknowledged_admission_reconciles_newer_floor_after_challenge_and_command_expire() {
    let f = fixture(false).await;
    let mut pending = f
        .app
        .witness_prepare_admission(&f.invitation, "Guest")
        .await
        .unwrap();
    f.state.lock().unwrap().mode = "advance_head_once";
    // Read returns the admission head, but independent freshness observes an
    // owner update. It persists that newer floor before rejecting the old proof.
    assert!(f.app.witness_admit(&mut pending, None).await.is_err());
    let acknowledged = pending
        .submitted
        .as_ref()
        .unwrap()
        .receipt
        .as_ref()
        .unwrap()
        .sequence;
    assert!(
        f.app
            .witness_position(&pending.pin)
            .unwrap()
            .unwrap()
            .sequence
            > acknowledged
    );
    pending.expires_at_ms = 1;
    pending.started = Instant::now() - Duration::from_secs(121);
    pending.submitted.as_mut().unwrap().command.expires_at_ms = 1;
    let WitnessAdmissionOutcome::Admitted(authority) =
        f.app.witness_admit(&mut pending, None).await.unwrap()
    else {
        panic!("acknowledged admission unexpectedly requested another approval")
    };
    {
        let state = f.state.lock().unwrap();
        assert_eq!(authority.head_id(), state.authority.head_id());
        assert_eq!(
            state
                .commands
                .iter()
                .filter(|x| x.0 == "device.admitted")
                .count(),
            1
        );
        assert_eq!(state.commands.iter().filter(|x| x.0 == "read").count(), 2);
        let reads = state
            .wire
            .iter()
            .filter_map(|bytes| {
                let request: Request = serde_json::from_slice(bytes).unwrap();
                let command: Command = decode_record(&request.command).unwrap().decode().unwrap();
                matches!(command.operation, Operation::Read).then_some(command)
            })
            .collect::<Vec<_>>();
        assert_ne!(reads[0].nonce, reads[1].nonce);
        assert!(reads[1].expires_at_ms > time());
    }
    f.app.close().await.unwrap();
}

#[tokio::test]
async fn a_known_local_fork_cannot_be_hidden_by_one_valid_admission_branch() {
    let mut f = fixture(false).await;
    let mut pending = f
        .app
        .witness_prepare_admission(&f.invitation, "Guest")
        .await
        .unwrap();
    {
        let state = f.state.lock().unwrap();
        let mut local = state.authority.clone();
        let first = owner_successor(&local, &state.owner, &state.witness);
        let second = owner_successor(&local, &state.owner, &state.witness);
        local.apply_config(first).unwrap();
        local.apply_config(second).unwrap();
        assert!(local.is_forked());
        f.app.authorities = Authorities(vec![local].into());
    }
    assert!(f.app.witness_admit(&mut pending, None).await.is_err());
    assert!(f.app.authorities.0[0].is_forked());
    f.app.close().await.unwrap();
}

#[tokio::test]
async fn concurrent_floor_advance_before_ack_handling_preserves_the_newer_floor() {
    let f = fixture(false).await;
    let mut pending = f
        .app
        .witness_prepare_admission(&f.invitation, "Guest")
        .await
        .unwrap();
    f.state.lock().unwrap().mode = "pause_ack";
    let concurrent = async {
        f.admit_committed.notified().await;
        let (pin, advanced) = {
            let mut state = f.state.lock().unwrap();
            state.sequence += 1;
            state.tip = Some(RecordId::from_bytes([93; 32]));
            (
                state.pin.clone(),
                Position {
                    sequence: state.sequence,
                    record_id: state.tip,
                },
            )
        };
        // Another independently verified response is persisted while this
        // request's older, valid mutation ACK is still in flight.
        f.app
            .record_witness_position(&pin, advanced.clone())
            .unwrap();
        f.release_admit.notify_one();
        advanced
    };
    let (result, advanced) = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::join!(f.app.witness_admit(&mut pending, None), concurrent)
    })
    .await
    .unwrap();
    assert!(matches!(
        result.unwrap(),
        WitnessAdmissionOutcome::Admitted(_)
    ));
    assert_eq!(
        f.app.witness_position(&pending.pin).unwrap(),
        Some(advanced)
    );
    assert_eq!(
        f.state
            .lock()
            .unwrap()
            .commands
            .iter()
            .filter(|command| command.0 == "device.admitted")
            .count(),
        1
    );
    f.app.close().await.unwrap();
}

#[tokio::test]
async fn admission_ack_exception_keeps_snapshot_and_atomic_fork_checks() {
    let f = fixture(false).await;
    let mut pending = f
        .app
        .witness_prepare_admission(&f.invitation, "Guest")
        .await
        .unwrap();
    assert!(matches!(
        f.app.witness_admit(&mut pending, None).await.unwrap(),
        WitnessAdmissionOutcome::Admitted(_)
    ));
    let submitted = pending.submitted.as_ref().unwrap();
    let receipt = submitted.receipt.as_ref().unwrap();
    let (encoded, position, challenge_request, challenge_ack) = {
        let state = f.state.lock().unwrap();
        let reply = state.replies.get(&submitted.signed.id()).unwrap();
        let request: Request = serde_json::from_slice(&state.wire[0]).unwrap();
        let challenge_request = decode_record(&request.command).unwrap();
        let challenge_ack = state
            .replies
            .get(&challenge_request.id())
            .unwrap()
            .receipt
            .clone()
            .unwrap();
        (
            reply.receipt.clone().unwrap(),
            Position {
                sequence: receipt.sequence,
                record_id: state.tip,
            },
            challenge_request,
            challenge_ack,
        )
    };
    let unrelated = Some(RecordId::from_bytes([94; 32]));
    for floor in [
        Position {
            sequence: receipt.sequence,
            record_id: unrelated,
        },
        Position {
            sequence: receipt.sequence - 1,
            record_id: unrelated,
        },
    ] {
        assert!(
            verify_ack(
                &pending.pin,
                &submitted.signed,
                &submitted.command,
                &encoded,
                "device.admitted",
                time(),
                Some(&floor)
            )
            .is_err()
        );
    }
    let later = Position {
        sequence: receipt.sequence + 1,
        record_id: unrelated,
    };
    assert!(
        verify_ack(
            &pending.pin,
            &submitted.signed,
            &submitted.command,
            &encoded,
            "device.admitted",
            time(),
            Some(&later)
        )
        .is_ok()
    );
    let challenge_command: Command = challenge_request.decode().unwrap();
    assert!(
        verify_ack(
            &pending.pin,
            &challenge_request,
            &challenge_command,
            &challenge_ack,
            "invitation.challenged",
            time(),
            Some(&later)
        )
        .is_err()
    );

    f.app
        .record_admission_receipt_position(
            &pending.pin,
            Position {
                sequence: receipt.sequence - 1,
                record_id: unrelated,
            },
            None,
        )
        .unwrap();
    assert_eq!(
        f.app.witness_position(&pending.pin).unwrap(),
        Some(position.clone())
    );
    assert!(
        f.app
            .record_admission_receipt_position(
                &pending.pin,
                Position {
                    sequence: receipt.sequence,
                    record_id: unrelated
                },
                receipt.previous
            )
            .is_err()
    );
    assert!(
        f.app
            .record_admission_receipt_position(
                &pending.pin,
                Position {
                    sequence: receipt.sequence + 1,
                    record_id: unrelated
                },
                unrelated
            )
            .is_err()
    );
    assert_eq!(
        f.app.witness_position(&pending.pin).unwrap(),
        Some(position)
    );
    f.app.close().await.unwrap();
}
