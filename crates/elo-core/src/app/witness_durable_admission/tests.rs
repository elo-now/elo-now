use super::*;
use crate::{
    authority::WitnessInvitationPolicy,
    witness::{
        Command, Freshness, HeadRequest, Position, Receipt,
        link::{self, Descriptor, InvitationSeed},
    },
};
use std::sync::{Arc, Mutex};

const API: &str = "https://api.example.test";
const PASSWORD: &str = "synthetic durable admission password";

fn time() -> u64 {
    now().unwrap().as_millis() as u64
}
fn sign(value: &impl Serialize, key: &SigningKey) -> SignedRecord {
    SignedRecord::sign(&serde_json::to_vec(value).unwrap(), key).unwrap()
}
fn encode(record: &SignedRecord) -> String {
    STANDARD.encode(record.bytes())
}

struct Mock {
    authority: Authority,
    owner: SigningKey,
    witness: SigningKey,
    invitation: VerifyingKey,
    pin: WitnessPin,
    sequence: u64,
    tip: Option<RecordId>,
    consumed: BTreeSet<RecordId>,
    commands: Vec<&'static str>,
    wire: Vec<Vec<u8>>,
    mode: &'static str,
}
impl Mock {
    fn command(
        &mut self,
        request: Request,
    ) -> std::result::Result<Response, axum::http::StatusCode> {
        use axum::http::StatusCode as Status;
        self.wire.push(serde_json::to_vec(&request).unwrap());
        let record = decode_record(&request.command).unwrap();
        let command: Command = record.decode().unwrap();
        assert_eq!(command.audience, self.pin.url);
        assert_eq!(command.space_id, self.authority.space());
        let candidate = match &command.operation {
            Operation::ChallengeV2 { credential, .. } | Operation::AdmitV2 { credential, .. } => {
                let record = decode_record(credential).unwrap();
                VerifiedCredential::verify(
                    record.bytes(),
                    &root_key(record.body()["root_public_key"].as_str().unwrap()).unwrap(),
                )
                .unwrap()
            }
            Operation::Read => {
                self.commands.push("read");
                if self.mode == "read_fail_once" {
                    self.mode = "normal";
                    return Err(Status::SERVICE_UNAVAILABLE);
                }
                if !self
                    .authority
                    .head()
                    .unwrap()
                    .members
                    .iter()
                    .any(|m| m.credential_ids.contains(&command.credential_id))
                {
                    return Err(Status::FORBIDDEN);
                }
                self.authority
                    .credential(command.credential_id)
                    .unwrap()
                    .clone()
            }
            _ => panic!("unexpected command"),
        };
        assert_eq!(candidate.id(), command.credential_id);
        record.verify_signature(candidate.key()).unwrap();
        let now = time();
        let mut response = Response {
            receipt: None,
            proof: None,
            challenge: None,
        };
        let event = match command.operation {
            Operation::Read => {
                response.proof = Some(self.authority.call_proof().unwrap());
                return Ok(response);
            }
            Operation::ChallengeV2 {
                request: join,
                client_nonce,
                ..
            } => {
                self.commands.push("challenge");
                let body = self
                    .authority
                    .verify_witness_join_request(&join, &candidate, now)
                    .unwrap();
                let id = decode_record(&join.device_request).unwrap().id();
                if self.consumed.contains(&id) {
                    return Err(Status::CONFLICT);
                }
                let possession =
                    decode_record(request.invitation_signature.as_ref().unwrap()).unwrap();
                assert_eq!(possession.body_bytes(), record.body_bytes());
                possession.verify_signature(&self.invitation).unwrap();
                let challenge = WitnessChallengeV2 {
                    v: 2,
                    kind: "witness.challenge".into(),
                    nonce: record::random_hex::<32>().unwrap(),
                    client_nonce,
                    space_id: self.authority.space(),
                    stream_id: self.authority.stream(),
                    policy_id: body.policy_id,
                    credential_id: candidate.id(),
                    request_id: id,
                    authority_head: self.authority.head_id().unwrap(),
                    issued_at_ms: now,
                    expires_at_ms: (now + 120_000).min(body.expires_at_ms),
                    witness_key_generation: 1,
                };
                response.challenge = Some(encode(&sign(&challenge, &self.witness)));
                "invitation.challenged_v2"
            }
            Operation::AdmitV2 { mut evidence, .. } => {
                self.commands.push("admit");
                if self.mode == "admit_not_received_once" {
                    self.mode = "normal";
                    return Err(Status::SERVICE_UNAVAILABLE);
                }
                let id = decode_record(&evidence.request.device_request)
                    .unwrap()
                    .id();
                if self.consumed.contains(&id) {
                    return Err(Status::CONFLICT);
                }
                let challenge: WitnessChallengeV2 = decode_record(&evidence.challenge)
                    .unwrap()
                    .decode()
                    .unwrap();
                assert_eq!(challenge.authority_head, command.authority_head);
                self.authority.add_credential(candidate);
                evidence.admitted_at_ms = now;
                let config = self
                    .authority
                    .prepare_witness_admission_v2(evidence, &self.witness)
                    .map_err(|_| Status::FORBIDDEN)?;
                self.authority.apply_config(config).unwrap();
                self.consumed.insert(id);
                "device.admitted_v2"
            }
            _ => unreachable!(),
        };
        self.sequence += 1;
        let receipt = sign(
            &Receipt {
                v: 1,
                kind: "witness.receipt".into(),
                audience: self.pin.url.clone(),
                sequence: self.sequence,
                previous: self.tip,
                request_id: record.id(),
                space_id: self.authority.space(),
                authority_head: self.authority.head_id().unwrap(),
                state_digest: "11".repeat(32),
                accepted_at_ms: now,
                event: event.into(),
                witness_key_generation: 1,
            },
            &self.witness,
        );
        self.tip = Some(receipt.id());
        response.receipt = Some(encode(&receipt));
        if event == "device.admitted_v2" && self.mode == "admit_ack_lost_once" {
            self.mode = "normal";
            return Err(Status::SERVICE_UNAVAILABLE);
        }
        if event == "device.admitted_v2" && self.mode == "read_fails_after_ack" {
            self.mode = "read_fail_once";
        }
        Ok(response)
    }
    fn head(&self, request: HeadRequest) -> Value {
        let now = time();
        json!({"freshness":encode(&sign(&Freshness {
            v:1, kind:"witness.freshness".into(), audience:self.pin.url.clone(),
            nonce:if self.mode == "wrong_nonce" { "55".repeat(32) } else { request.nonce },
            space_id:request.space_id, stream_id:request.stream_id,
            authority_head:self.authority.head_id().unwrap(), position:Position { sequence:self.sequence, record_id:self.tip },
            issued_at_ms:now, expires_at_ms:now+30_000, witness_key_generation:1,
        }, &self.witness))})
    }
    fn remove_candidate(&mut self, candidate: RecordId) {
        let mut config = self.authority.head().unwrap().clone();
        config.sequence += 1;
        config.previous_config_id = self.authority.head_id();
        config.nonce = record::random_hex::<16>().unwrap();
        config.witness_evidence = None;
        config
            .members
            .retain(|m| !m.credential_ids.contains(&candidate));
        let config = self
            .authority
            .prepare_witness_owner_config(&config.sign(&self.owner).unwrap(), &self.witness)
            .unwrap();
        self.authority.apply_config(config).unwrap();
        self.sequence += 1;
        self.tip = Some(RecordId::from_bytes([77; 32]));
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
    _server: Running,
    app: ClientApp,
    owner: ClientApp,
    invitation: VerifiedDescriptor,
    state: Arc<Mutex<Mock>>,
}
async fn fixture(approval: bool) -> Fixture {
    let temp = tempfile::tempdir().unwrap();
    let mut app = ProfileDraft::new()
        .unwrap()
        .save(temp.path().join("candidate"), PASSWORD.into(), "Guest")
        .await
        .unwrap();
    let mut owner = ProfileDraft::new()
        .unwrap()
        .save(temp.path().join("owner"), PASSWORD.into(), "Owner")
        .await
        .unwrap();
    let credential = owner.session.credential().clone();
    let owner_key = owner.session.signing_key().clone();
    let root = root_key(
        credential.record().body()["root_public_key"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let witness = SigningKey::from_bytes(&[3; 32]);
    let pin = WitnessPin {
        url: "https://witness.example.test/witness/v1".into(),
        public_key: record::encode_hex(witness.verifying_key().as_bytes()),
        key_generation: 1,
    };
    let stream = StreamId::from_bytes([4; 16]);
    let genesis = sign(
        &SpaceGenesis {
            v: 4,
            kind: "space.genesis".into(),
            nonce: stream.to_string(),
            issuer_identity: credential.identity(),
            owners: vec![Owner {
                identity_id: credential.identity(),
                root_public_key: record::encode_hex(root.as_bytes()),
            }],
            controller_credential_id: credential.id(),
            witness: Some(pin.clone()),
        },
        &owner_key,
    );
    let mut authority = Authority::new(
        genesis.bytes(),
        genesis.id().to_string().parse().unwrap(),
        &root,
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
            root_public_key: record::encode_hex(root.as_bytes()),
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
        .apply_config(config.sign(&owner_key).unwrap())
        .unwrap();
    let seed = InvitationSeed::generate().unwrap();
    let key = seed.invitation_public_key().unwrap();
    let policy = sign(
        &WitnessInvitationPolicy {
            v: 1,
            kind: "witness.invitation".into(),
            nonce: record::random_hex::<16>().unwrap(),
            space_id: authority.space(),
            stream_id: stream,
            authority_head: authority.head_id().unwrap(),
            issuer_credential_id: credential.id(),
            invitation_public_key: record::encode_hex(key.as_bytes()),
            not_before_ms: time() - 7_200_000,
            expires_at_ms: time() + 86_400_000,
            require_approval: approval,
            max_uses: 5,
            witness_key_generation: 1,
        },
        &owner_key,
    );
    let descriptor = Descriptor {
        v: 1,
        kind: "witness.invitation.descriptor".into(),
        name: "Test Space".into(),
        address: space_service::SpaceAddress {
            url: format!("{API}/spaces/{}/team/v1/spaces", "ab".repeat(32)),
            scope: team::TeamScope {
                space: authority.space(),
                stream,
                root: record::encode_hex(root.as_bytes()),
                controller: credential.id(),
            },
            message_lifetime_seconds: crate::message_retention::MessageRetention::Hours6,
            service_credential: None,
        },
        witness: pin.clone(),
        proof: authority.call_proof().unwrap(),
        policy: encode(&policy),
        invitation_public_key: record::encode_hex(key.as_bytes()),
    };
    let encrypted = link::seal(&descriptor, &owner_key, seed, API, &pin, time()).unwrap();
    let invitation = encrypted
        .link
        .open(&encrypted.ciphertext, API, &pin, time())
        .unwrap();
    app.configure_witness_pin(Some(pin.clone())).unwrap();
    owner.configure_witness_pin(Some(pin.clone())).unwrap();
    let state = Arc::new(Mutex::new(Mock {
        authority,
        owner: owner_key,
        witness,
        invitation: key,
        pin,
        sequence: 2,
        tip: Some(RecordId::from_bytes([5; 32])),
        consumed: BTreeSet::new(),
        commands: vec![],
        wire: vec![],
        mode: "normal",
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    app.witness_test_url = Some(endpoint.clone());
    owner.witness_test_url = Some(endpoint);
    let commands = state.clone();
    let heads = state.clone();
    let router = axum::Router::new()
        .route(
            "/command",
            axum::routing::post(move |axum::Json(request): axum::Json<Request>| async move {
                commands.lock().unwrap().command(request).map(axum::Json)
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
    let server = Running(tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    }));
    Fixture {
        _temp: temp,
        _server: server,
        app,
        owner,
        invitation,
        state,
    }
}
async fn restart(app: ClientApp) -> ClientApp {
    let directory = app.directory.clone();
    let pin = app.witness_pin.clone();
    let endpoint = app.witness_test_url.clone();
    app.close().await.unwrap();
    let mut restored = ClientApp::open(directory, PASSWORD.into(), false)
        .await
        .unwrap();
    restored.configure_witness_pin(pin).unwrap();
    restored.witness_test_url = endpoint;
    restored
}
fn age_request(app: &mut ClientApp, id: RecordId) -> RecordId {
    let mut state = app.durable_state().unwrap();
    let mut pending = state.entries.remove(&id).unwrap();
    let mut request: WitnessJoinRequest = decode_record(&pending.packet.request.device_request)
        .unwrap()
        .decode()
        .unwrap();
    request.issued_at_ms -= 3_600_000;
    request.expires_at_ms -= 3_600_000;
    let body = serde_json::to_vec(&request).unwrap();
    let device = SignedRecord::sign(&body, app.session.signing_key()).unwrap();
    pending.packet.request.device_request = encode(&device);
    pending.packet.request.invitation_request = encode(
        &SignedRecord::sign(
            &body,
            &SigningKey::from_bytes(&pending.invitation_signing_seed),
        )
        .unwrap(),
    );
    pending.packet.request_id = device.id();
    pending.packet.expires_at_ms = request.expires_at_ms;
    state.entries.insert(device.id(), pending);
    app.write_durable_state(&state).unwrap();
    device.id()
}

fn existing_approval(
    authority: &Authority,
    packet: &DurableAdmissionRequest,
    issuer: RecordId,
    key: &SigningKey,
    readmission: bool,
) -> SignedRecord {
    sign(
        &WitnessApprovalV2 {
            v: 2,
            kind: "witness.approval".into(),
            nonce: record::random_hex::<16>().unwrap(),
            space_id: authority.space(),
            stream_id: authority.stream(),
            authority_head: authority.head_id().unwrap(),
            issuer_credential_id: issuer,
            request_id: packet.request_id,
            readmission,
            expires_at_ms: packet.expires_at_ms,
        },
        key,
    )
}

fn update_members(state: &mut Mock, change: impl FnOnce(&mut StreamConfig)) {
    let mut next = state.authority.head().unwrap().clone();
    next.sequence += 1;
    next.previous_config_id = state.authority.head_id();
    next.nonce = record::random_hex::<16>().unwrap();
    next.witness_evidence = None;
    change(&mut next);
    next.members.sort_by_key(|m| m.identity_id);
    next.owner_credential_ids.sort();
    let signed = state
        .authority
        .prepare_witness_owner_config(&next.sign(&state.owner).unwrap(), &state.witness)
        .unwrap();
    state.authority.apply_config(signed).unwrap();
}

#[tokio::test]
async fn existing_approval_rejects_wrong_request_signature_scope_and_expiry() {
    let mut f = fixture(true).await;
    let packet = f
        .app
        .witness_prepare_durable_admission(&f.invitation, "Guest")
        .unwrap();
    let authority = f.state.lock().unwrap().authority.clone();
    let approval = existing_approval(
        &authority,
        &packet,
        f.owner.session.credential().id(),
        f.owner.session.signing_key(),
        false,
    );
    f.owner
        .witness_verify_existing_durable_approval(&authority, &packet, &approval)
        .unwrap();
    for change in 0..5 {
        let mut body: WitnessApprovalV2 = approval.decode().unwrap();
        match change {
            0 => body.request_id = RecordId::from_bytes([99; 32]),
            1 => body.stream_id = StreamId::from_bytes([99; 16]),
            2 => body.expires_at_ms = time(),
            3 => body.expires_at_ms = packet.expires_at_ms + 1,
            _ => (),
        }
        let key = if change == 4 {
            f.app.session.signing_key()
        } else {
            f.owner.session.signing_key()
        };
        assert!(
            f.owner
                .witness_verify_existing_durable_approval(&authority, &packet, &sign(&body, key))
                .is_err(),
            "change {change}"
        );
    }
    let mut changed_packet = packet.clone();
    changed_packet.request.contact = encode(
        &invite::shared::contact(
            f.app.session.credential(),
            f.app.session.signing_key(),
            "Different candidate name",
            packet.expires_at_ms / 1_000,
        )
        .unwrap(),
    );
    assert!(
        f.owner
            .witness_verify_existing_durable_approval(&authority, &changed_packet, &approval)
            .is_err()
    );
    assert!(f.state.lock().unwrap().commands.is_empty());
    f.app.close().await.unwrap();
    f.owner.close().await.unwrap();
}

#[tokio::test]
async fn existing_approval_accepts_another_owner_but_not_removal_or_regrant() {
    let mut f = fixture(true).await;
    let packet = f
        .app
        .witness_prepare_durable_admission(&f.invitation, "Guest")
        .unwrap();
    let other_root = SigningKey::from_bytes(&[90; 32]);
    let other_key = SigningKey::from_bytes(&[91; 32]);
    let other_age = age::x25519::Identity::generate();
    let other = crate::identity::DeviceCredential::issue(
        &other_root,
        &other_key.verifying_key(),
        &other_age.to_public(),
    )
    .unwrap();
    {
        let mut state = f.state.lock().unwrap();
        state.authority.add_credential(other.clone());
        let mut member = state.authority.head().unwrap().members[0].clone();
        member.identity_id = other.identity();
        member.root_public_key = record::encode_hex(other_root.verifying_key().as_bytes());
        member.credential_ids = vec![other.id()];
        update_members(&mut state, |config| {
            config.members.push(member.clone());
            config.owner_credential_ids.push(other.id());
        });
        let approval = existing_approval(&state.authority, &packet, other.id(), &other_key, false);
        f.owner
            .witness_verify_existing_durable_approval(&state.authority, &packet, &approval)
            .unwrap();
        update_members(&mut state, |config| {
            config.members.retain(|m| m.identity_id != other.identity());
            config.owner_credential_ids.retain(|id| *id != other.id());
        });
        assert!(
            f.owner
                .witness_verify_existing_durable_approval(&state.authority, &packet, &approval)
                .is_err()
        );
        update_members(&mut state, |config| {
            config.members.push(member);
            config.owner_credential_ids.push(other.id());
        });
        assert!(
            f.owner
                .witness_verify_existing_durable_approval(&state.authority, &packet, &approval)
                .is_err()
        );
        let renewed = existing_approval(&state.authority, &packet, other.id(), &other_key, false);
        f.owner
            .witness_verify_existing_durable_approval(&state.authority, &packet, &renewed)
            .unwrap();
    }
    f.app.close().await.unwrap();
    f.owner.close().await.unwrap();
}

#[tokio::test]
async fn existing_approval_requires_explicit_consent_after_the_last_identity_removal() {
    let mut f = fixture(true).await;
    let packet = f
        .app
        .witness_prepare_durable_admission(&f.invitation, "Guest")
        .unwrap();
    {
        let mut state = f.state.lock().unwrap();
        let candidate = f.app.session.credential();
        state.authority.add_credential(candidate.clone());
        let mut member = state.authority.head().unwrap().members[0].clone();
        member.identity_id = candidate.identity();
        member.root_public_key = candidate.record().body()["root_public_key"]
            .as_str()
            .unwrap()
            .into();
        member.credential_ids = vec![candidate.id()];
        member.capabilities = vec![Capability::Read, Capability::Post];
        update_members(&mut state, |config| config.members.push(member));
        let stale = existing_approval(
            &state.authority,
            &packet,
            f.owner.session.credential().id(),
            f.owner.session.signing_key(),
            true,
        );
        update_members(&mut state, |config| {
            config
                .members
                .retain(|m| m.identity_id != candidate.identity());
        });
        assert!(
            f.owner
                .witness_verify_existing_durable_approval(&state.authority, &packet, &stale)
                .is_err()
        );
        let missing_readmission = existing_approval(
            &state.authority,
            &packet,
            f.owner.session.credential().id(),
            f.owner.session.signing_key(),
            false,
        );
        assert!(
            f.owner
                .witness_verify_existing_durable_approval(
                    &state.authority,
                    &packet,
                    &missing_readmission
                )
                .is_err()
        );
        let valid = existing_approval(
            &state.authority,
            &packet,
            f.owner.session.credential().id(),
            f.owner.session.signing_key(),
            true,
        );
        f.owner
            .witness_verify_existing_durable_approval(&state.authority, &packet, &valid)
            .unwrap();
    }
    f.app.close().await.unwrap();
    f.owner.close().await.unwrap();
}

#[tokio::test]
async fn durable_pending_waits_an_hour_and_survives_both_profile_restarts() {
    let mut f = fixture(true).await;
    let packet = f
        .app
        .witness_prepare_durable_admission(&f.invitation, "Guest")
        .unwrap();
    let id = age_request(&mut f.app, packet.request_id);
    assert!(matches!(
        f.app
            .witness_finalize_durable_admission(id, API, None)
            .await
            .unwrap(),
        DurableAdmissionOutcome::ApprovalRequired
    ));
    assert!(f.state.lock().unwrap().commands.is_empty());
    f.app = restart(f.app).await;
    f.owner = restart(f.owner).await;
    let packet = f.app.witness_durable_admissions().unwrap().pop().unwrap();
    assert_eq!(packet.request_id, id);
    assert_eq!(packet.name, "Test Space");
    let base = f.state.lock().unwrap().authority.clone();
    let approval = f
        .owner
        .witness_approve_durable_admission(&base, &packet, false)
        .await
        .unwrap();
    let result = f
        .app
        .witness_finalize_durable_admission(id, API, Some(&approval))
        .await
        .unwrap();
    let DurableAdmissionOutcome::Admitted(authority) = result else {
        panic!("missing membership");
    };
    assert_eq!(f.app.witness_durable_admissions().unwrap().len(), 1);
    f.app
        .witness_complete_durable_admission(id, &authority)
        .unwrap();
    assert!(f.app.witness_durable_admissions().unwrap().is_empty());
    f.app.close().await.unwrap();
    f.owner.close().await.unwrap();
}

#[tokio::test]
async fn lost_admit_ack_recovers_after_restart_without_repeating_mutation() {
    let mut f = fixture(false).await;
    let packet = f
        .app
        .witness_prepare_durable_admission(&f.invitation, "Guest")
        .unwrap();
    f.state.lock().unwrap().mode = "admit_ack_lost_once";
    assert!(
        f.app
            .witness_finalize_durable_admission(packet.request_id, API, None)
            .await
            .is_err()
    );
    f.app = restart(f.app).await;
    assert!(matches!(
        f.app
            .witness_finalize_durable_admission(packet.request_id, API, None)
            .await
            .unwrap(),
        DurableAdmissionOutcome::Admitted(_)
    ));
    {
        let state = f.state.lock().unwrap();
        assert_eq!(state.commands, vec!["challenge", "admit", "read"]);
    }
    f.app.close().await.unwrap();
    f.owner.close().await.unwrap();
}

#[tokio::test]
async fn submitted_admission_precedes_waiting_approval_and_completion_does_not_revive_it() {
    let mut f = fixture(true).await;
    let waiting = f
        .app
        .witness_prepare_durable_admission(&f.invitation, "Earlier name")
        .unwrap();
    let accepted = f
        .app
        .witness_prepare_durable_admission(&f.invitation, "Current name")
        .unwrap();
    let authority = f.state.lock().unwrap().authority.clone();
    let approval = existing_approval(
        &authority,
        &accepted,
        f.owner.session.credential().id(),
        f.owner.session.signing_key(),
        false,
    );
    f.state.lock().unwrap().mode = "read_fails_after_ack";
    assert!(
        f.app
            .witness_finalize_durable_admission(accepted.request_id, API, Some(&approval))
            .await
            .is_err()
    );
    f.app = restart(f.app).await;
    let pending = f.app.witness_durable_admissions().unwrap();
    assert_eq!(pending.len(), 2);
    assert_eq!(pending[0].request_id, accepted.request_id);
    assert_eq!(pending[1].request_id, waiting.request_id);
    assert!(
        f.app
            .witness_prepare_durable_admission(&f.invitation, "Another name")
            .is_err(),
        "an uncertain admission cannot be replaced by another mutation"
    );
    let (recovered, authority) = f
        .app
        .witness_reconcile_pending_scope(&accepted.address.scope, API)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(recovered.request_id, accepted.request_id);
    assert!(
        f.app
            .witness_complete_durable_admission(waiting.request_id, &authority)
            .is_err(),
        "current membership must prove the exact completed request"
    );
    assert_eq!(f.app.witness_durable_admissions().unwrap().len(), 2);
    f.app
        .witness_complete_durable_admission(recovered.request_id, &authority)
        .unwrap();
    f.app = restart(f.app).await;
    assert!(f.app.witness_durable_admissions().unwrap().is_empty());
    assert!(
        f.app
            .witness_reconcile_pending_scope(&accepted.address.scope, API)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        f.state.lock().unwrap().commands,
        ["challenge", "admit", "read", "read"]
    );
    f.app.close().await.unwrap();
    f.owner.close().await.unwrap();
}

#[tokio::test]
async fn scope_recovery_matches_the_accepted_request_among_multiple_uncertain_submissions() {
    let mut f = fixture(false).await;
    let first = f
        .app
        .witness_prepare_durable_admission(&f.invitation, "First name")
        .unwrap();
    let second = f
        .app
        .witness_prepare_durable_admission(&f.invitation, "Second name")
        .unwrap();
    // The first durable map entry was never accepted. Recovery must continue
    // to the later exact request rather than treating the first mismatch as final.
    let (unreceived, accepted) = if first.request_id < second.request_id {
        (first, second)
    } else {
        (second, first)
    };
    f.state.lock().unwrap().mode = "admit_not_received_once";
    assert!(
        f.app
            .witness_finalize_durable_admission(unreceived.request_id, API, None)
            .await
            .is_err()
    );
    f.state.lock().unwrap().mode = "admit_ack_lost_once";
    assert!(
        f.app
            .witness_finalize_durable_admission(accepted.request_id, API, None)
            .await
            .is_err()
    );
    f.app = restart(f.app).await;
    assert_eq!(
        f.app.witness_durable_admissions().unwrap()[0].request_id,
        unreceived.request_id
    );
    let (recovered, authority) = f
        .app
        .witness_reconcile_pending_scope(&accepted.address.scope, API)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(recovered.request_id, accepted.request_id);
    assert_eq!(
        f.app.witness_durable_admissions().unwrap().len(),
        2,
        "read-only recovery retains both submissions until durable installation"
    );
    assert_eq!(
        f.state.lock().unwrap().commands,
        ["challenge", "admit", "challenge", "admit", "read"]
    );
    f.app
        .witness_complete_durable_admission(recovered.request_id, &authority)
        .unwrap();
    assert!(f.app.witness_durable_admissions().unwrap().is_empty());
    f.app.close().await.unwrap();
    f.owner.close().await.unwrap();
}

#[tokio::test]
async fn unreceived_admit_requires_read_and_a_new_challenge_before_retry() {
    let mut f = fixture(false).await;
    let packet = f
        .app
        .witness_prepare_durable_admission(&f.invitation, "Guest")
        .unwrap();
    f.state.lock().unwrap().mode = "admit_not_received_once";
    assert!(
        f.app
            .witness_finalize_durable_admission(packet.request_id, API, None)
            .await
            .is_err()
    );
    f.app = restart(f.app).await;
    assert!(matches!(
        f.app
            .witness_finalize_durable_admission(packet.request_id, API, None)
            .await
            .unwrap(),
        DurableAdmissionOutcome::Admitted(_)
    ));
    {
        let state = f.state.lock().unwrap();
        assert_eq!(
            state.commands,
            vec!["challenge", "admit", "read", "challenge", "admit", "read"]
        );
    }
    f.app.close().await.unwrap();
    f.owner.close().await.unwrap();
}

#[tokio::test]
async fn acknowledged_admit_retries_only_reads_and_denies_removed_membership() {
    let mut f = fixture(false).await;
    let packet = f
        .app
        .witness_prepare_durable_admission(&f.invitation, "Guest")
        .unwrap();
    f.state.lock().unwrap().mode = "read_fails_after_ack";
    assert!(
        f.app
            .witness_finalize_durable_admission(packet.request_id, API, None)
            .await
            .is_err()
    );
    f.app = restart(f.app).await;
    f.state
        .lock()
        .unwrap()
        .remove_candidate(f.app.session.credential().id());
    assert!(
        f.app
            .witness_finalize_durable_admission(packet.request_id, API, None)
            .await
            .is_err()
    );
    {
        let state = f.state.lock().unwrap();
        assert_eq!(state.commands, vec!["challenge", "admit", "read", "read"]);
    }
    assert_eq!(f.app.witness_durable_admissions().unwrap().len(), 1);
    f.app.close().await.unwrap();
    f.owner.close().await.unwrap();
}

#[tokio::test]
async fn native_pins_exact_credential_and_fresh_head_are_required() {
    let mut f = fixture(false).await;
    let packet = f
        .app
        .witness_prepare_durable_admission(&f.invitation, "Guest")
        .unwrap();
    assert!(
        f.app
            .witness_finalize_durable_admission(
                packet.request_id,
                "https://other.example.test",
                None
            )
            .await
            .is_err()
    );
    let original = f.app.durable_state().unwrap();
    let mut changed = f.app.durable_state().unwrap();
    changed
        .entries
        .get_mut(&packet.request_id)
        .unwrap()
        .packet
        .credential = STANDARD.encode(f.owner.session.credential().record().bytes());
    f.app.write_durable_state(&changed).unwrap();
    assert!(
        f.app
            .witness_finalize_durable_admission(packet.request_id, API, None)
            .await
            .is_err()
    );
    f.app.write_durable_state(&original).unwrap();
    let pin = f.app.witness_pin.clone();
    f.app.configure_witness_pin(None).unwrap();
    assert!(
        f.app
            .witness_finalize_durable_admission(packet.request_id, API, None)
            .await
            .is_err()
    );
    f.app.configure_witness_pin(pin).unwrap();
    assert!(f.state.lock().unwrap().commands.is_empty());
    f.state.lock().unwrap().mode = "wrong_nonce";
    assert!(
        f.app
            .witness_finalize_durable_admission(packet.request_id, API, None)
            .await
            .is_err()
    );
    f.state.lock().unwrap().mode = "normal";
    assert!(matches!(
        f.app
            .witness_finalize_durable_admission(packet.request_id, API, None)
            .await
            .unwrap(),
        DurableAdmissionOutcome::Admitted(_)
    ));
    f.app.close().await.unwrap();
    f.owner.close().await.unwrap();
}

#[tokio::test]
async fn pending_is_encrypted_before_network_and_never_exports_invitation_key() {
    let mut f = fixture(false).await;
    let key = f.invitation.invitation_signing_key().to_bytes();
    let packet = f
        .app
        .witness_prepare_durable_admission(&f.invitation, "Guest")
        .unwrap();
    let again = f
        .app
        .witness_prepare_durable_admission(&f.invitation, "Guest")
        .unwrap();
    assert_eq!(again.request_id, packet.request_id);
    let path = f.app.directory.join(STATE_FILE);
    let encrypted = vault::read_private(&path).unwrap();
    assert!(encrypted.starts_with(b"age-encryption.org/v1"));
    assert!(!encrypted.windows(key.len()).any(|part| part == key));
    let public = serde_json::to_vec(&packet).unwrap();
    let encoded = STANDARD.encode(key);
    assert!(!String::from_utf8(public).unwrap().contains(&encoded));
    assert!(f.state.lock().unwrap().commands.is_empty());
    f.app
        .witness_finalize_durable_admission(packet.request_id, API, None)
        .await
        .unwrap();
    {
        let state = f.state.lock().unwrap();
        for request in &state.wire {
            assert!(!String::from_utf8_lossy(request).contains(&encoded));
        }
    }
    f.app
        .witness_cancel_durable_admission(packet.request_id)
        .unwrap();
    assert!(f.app.witness_durable_admissions().unwrap().is_empty());
    f.app.close().await.unwrap();
    f.owner.close().await.unwrap();
}
