use super::*;
use crate::journal::{Activation, Journal};
use ed25519_dalek::SigningKey;
use elo_core::{
    authority::{
        ConfigAction, Member, Owner, SpaceGenesis, StreamConfig, WitnessAdmissionEvidence,
        WitnessInvitationPolicy, WitnessPin,
    },
    invite::shared,
};
use serde::Serialize;
use tempfile::TempDir;

const NOW: u64 = 1_800_000_000_000;
const URL: &str = "https://witness.example.test/witness/v1";

struct Device {
    root: SigningKey,
    key: SigningKey,
    credential: VerifiedCredential,
}
fn device(seed: u8) -> Device {
    let root = SigningKey::from_bytes(&[seed; 32]);
    let key = SigningKey::from_bytes(&[seed + 1; 32]);
    let age = age::x25519::Identity::generate();
    let credential =
        DeviceCredential::issue(&root, &key.verifying_key(), &age.to_public()).unwrap();
    Device {
        root,
        key,
        credential,
    }
}
fn signed(body: &impl Serialize, key: &SigningKey) -> SignedRecord {
    SignedRecord::sign(&serde_json::to_vec(body).unwrap(), key).unwrap()
}
fn encoded(record: &SignedRecord) -> String {
    STANDARD.encode(record.bytes())
}
fn command(authority: &Authority, actor: &Device, operation: Operation) -> Request {
    let body = Command {
        v: 1,
        kind: "witness.command".into(),
        nonce: record::random_hex::<32>().unwrap(),
        audience: URL.into(),
        space_id: authority.space(),
        stream_id: authority.stream(),
        credential_id: actor.credential.id(),
        authority_head: authority.head_id().unwrap(),
        issued_at_ms: NOW,
        expires_at_ms: NOW + 60_000,
        operation,
    };
    Request {
        command: encoded(&signed(&body, &actor.key)),
        invitation_signature: None,
        proof: None,
        registration_work: None,
    }
}
struct Fixture {
    directory: TempDir,
    owner: Device,
    guest: Device,
    invitation: SigningKey,
    engine: Engine,
    authority: Authority,
    pin: WitnessPin,
    registration: Vec<u8>,
}

#[test]
fn registration_work_cannot_be_reused_with_a_changed_command_or_proof() {
    let fixture = Fixture::new();
    let mut request: Request = serde_json::from_slice(&fixture.registration).unwrap();
    request.verify_registration_work().unwrap();
    let original = request.command.clone();
    request.command.push('x');
    assert!(request.verify_registration_work().is_err());
    request.command = original;
    request.proof.as_mut().unwrap().genesis.push('x');
    assert!(request.verify_registration_work().is_err());
    let mut request: Request = serde_json::from_slice(&fixture.registration).unwrap();
    let config = request.proof.as_ref().unwrap().configs[0].clone();
    request.proof.as_mut().unwrap().configs.push(config);
    assert!(request.verify_registration_work().is_err());
}

#[test]
fn registration_budget_groups_ipv6_networks_and_normalizes_mapped_ipv4() {
    let key = |ip: &str, day| registration_network(ip.parse().unwrap(), day);
    assert_eq!(key("2001:db8:1:2::1", 1), key("2001:db8:1:2::ffff", 1));
    assert_ne!(key("2001:db8:1:2::1", 1), key("2001:db8:1:3::1", 1));
    assert_eq!(key("192.0.2.1", 1), key("::ffff:192.0.2.1", 1));
    assert_ne!(key("192.0.2.1", 1), key("192.0.2.1", 2));
    assert_eq!(key("192.0.2.1", 1).len(), 64);
}
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let owner = device(1);
        let guest = device(3);
        let witness = SigningKey::from_bytes(&[5; 32]);
        let invitation = SigningKey::from_bytes(&[6; 32]);
        let pin = WitnessPin {
            url: URL.into(),
            public_key: record::encode_hex(witness.verifying_key().as_bytes()),
            key_generation: 1,
        };
        let stream = StreamId::from_bytes([7; 16]);
        let genesis = signed(
            &SpaceGenesis {
                v: 4,
                kind: "space.genesis".into(),
                nonce: stream.to_string(),
                issuer_identity: owner.credential.identity(),
                owners: vec![Owner {
                    identity_id: owner.credential.identity(),
                    root_public_key: record::encode_hex(owner.root.verifying_key().as_bytes()),
                }],
                controller_credential_id: owner.credential.id(),
                witness: Some(pin.clone()),
            },
            &owner.key,
        );
        let mut authority = Authority::new(
            genesis.bytes(),
            genesis.id().to_string().parse().unwrap(),
            &owner.root.verifying_key(),
            owner.credential.clone(),
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
            controller_credential_id: owner.credential.id(),
            members: vec![Member {
                identity_id: owner.credential.identity(),
                identity_type: "HUMAN".into(),
                root_public_key: record::encode_hex(owner.root.verifying_key().as_bytes()),
                capabilities: vec![
                    Capability::Read,
                    Capability::Post,
                    Capability::ShareHistory,
                    Capability::Manage,
                ],
                credential_ids: vec![owner.credential.id()],
                external: false,
            }],
            owner_credential_ids: vec![owner.credential.id()],
            action: ConfigAction {
                operation: "create".into(),
                actor_identity: owner.credential.identity(),
                request_record_id: None,
            },
            chat_kind: Some(ChatKind::Chat),
            recovery: None,
            witness_evidence: None,
        };
        authority
            .apply_config(config.sign(&owner.key).unwrap())
            .unwrap();
        let keypath = directory.path().join("key");
        elo_core::vault::write_private(&keypath, &witness.to_bytes(), false).unwrap();
        let mut journal =
            Journal::open(&directory.path().join("data"), &keypath, pin.clone(), NOW).unwrap();
        let mut request = command(&authority, &owner, Operation::Register);
        request.proof = Some(authority.call_proof().unwrap());
        assert!(request.verify_registration_work().is_err());
        request.solve_registration_work().unwrap();
        let registration = serde_json::to_vec(&request).unwrap();
        activate(
            &mut journal,
            Position {
                sequence: 0,
                record_id: None,
            },
        );
        let mut engine = Engine { journal };
        engine
            .apply(request, "127.0.0.1".parse().unwrap(), NOW)
            .unwrap();
        Self {
            directory,
            owner,
            guest,
            invitation,
            engine,
            authority,
            pin,
            registration,
        }
    }
    fn apply(&mut self, request: Request) -> Result<Response> {
        self.engine
            .apply(request, "127.0.0.1".parse().unwrap(), NOW)
    }
    fn policy(&mut self, approval: bool, max_uses: u64) -> SignedRecord {
        let policy = signed(
            &WitnessInvitationPolicy {
                v: 1,
                kind: "witness.invitation".into(),
                nonce: record::random_hex::<16>().unwrap(),
                space_id: self.authority.space(),
                stream_id: self.authority.stream(),
                authority_head: self.authority.head_id().unwrap(),
                issuer_credential_id: self.owner.credential.id(),
                invitation_public_key: record::encode_hex(
                    self.invitation.verifying_key().as_bytes(),
                ),
                not_before_ms: NOW - 1000,
                expires_at_ms: NOW + 3_600_000,
                require_approval: approval,
                max_uses,
                witness_key_generation: 1,
            },
            &self.owner.key,
        );
        self.apply(command(
            &self.authority,
            &self.owner,
            Operation::RegisterInvitation {
                policy: encoded(&policy),
            },
        ))
        .unwrap();
        policy
    }
    fn evidence(&mut self, policy: &SignedRecord) -> WitnessAdmissionEvidence {
        let mut request = command(
            &self.authority,
            &self.guest,
            Operation::Challenge {
                policy_id: policy.id(),
                credential: encoded(self.guest.credential.record()),
                client_nonce: record::random_hex::<32>().unwrap(),
            },
        );
        let record = decode(&request.command).unwrap();
        request.invitation_signature = Some(encoded(
            &SignedRecord::sign(record.body_bytes(), &self.invitation).unwrap(),
        ));
        let challenge = self.apply(request).unwrap().challenge.unwrap();
        let contact = shared::contact(
            &self.guest.credential,
            &self.guest.key,
            "Guest",
            NOW / 1000 + 3600,
        )
        .unwrap();
        let intent = WitnessAdmissionIntent {
            v: 1,
            kind: "witness.admission".into(),
            nonce: record::random_hex::<32>().unwrap(),
            space_id: self.authority.space(),
            stream_id: self.authority.stream(),
            policy_id: policy.id(),
            challenge_id: decode(&challenge).unwrap().id(),
            credential_id: self.guest.credential.id(),
            contact_id: contact.id(),
        };
        WitnessAdmissionEvidence {
            policy: encoded(policy),
            challenge,
            device_intent: encoded(&signed(&intent, &self.guest.key)),
            invitation_intent: encoded(&signed(&intent, &self.invitation)),
            contact: encoded(&contact),
            approval: None,
            admitted_at_ms: 0,
        }
    }
    fn admission(&self, evidence: WitnessAdmissionEvidence) -> Request {
        command(
            &self.authority,
            &self.guest,
            Operation::Admit {
                credential: encoded(self.guest.credential.record()),
                evidence,
            },
        )
    }
    fn refresh(&mut self) {
        self.authority = load(
            &self.engine.journal.db,
            self.authority.space(),
            self.authority.stream(),
            &self.pin,
        )
        .unwrap();
    }
}
fn activate(journal: &mut Journal, position: Position) {
    let startup = journal.startup().unwrap();
    journal
        .activate(
            Activation {
                startup_nonce: startup.startup_nonce,
                expected_position: position,
                public_key: startup.public_key,
                key_generation: 1,
                expires_at_ms: NOW + 60_000,
            },
            NOW,
        )
        .unwrap();
}

#[test]
fn offline_owner_admission_is_atomic_idempotent_and_bounded_by_last_use() {
    let mut f = Fixture::new();
    let policy = f.policy(false, 1);
    let evidence = f.evidence(&policy);
    let first = f.admission(evidence.clone());
    let duplicate = f.admission(evidence);
    let first_json = serde_json::to_vec(&first).unwrap();
    let receipt = f.apply(first).unwrap().receipt;
    f.refresh();
    assert!(require_read(&f.authority, f.guest.credential.id()).is_ok());
    assert!(!f.authority.can_manage(f.guest.credential.id()));
    assert_eq!(
        f.apply(serde_json::from_slice(&first_json).unwrap())
            .unwrap()
            .receipt,
        receipt
    );
    assert!(f.apply(duplicate).is_err());
    let uses: i64 = f
        .engine
        .journal
        .db
        .query_row(
            "SELECT uses FROM policies WHERE id=?1",
            [policy.id().to_string()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(uses, 1);
}

#[test]
fn revocation_fences_an_already_issued_challenge() {
    let mut f = Fixture::new();
    let policy = f.policy(false, 3);
    let evidence = f.evidence(&policy);
    f.apply(command(
        &f.authority,
        &f.owner,
        Operation::RevokeInvitation {
            policy_id: policy.id(),
        },
    ))
    .unwrap();
    assert!(f.apply(f.admission(evidence)).is_err());
    f.refresh();
    assert_eq!(f.authority.head().unwrap().members.len(), 1);
}

#[test]
fn tampered_admission_rolls_back_challenge_and_usage() {
    let mut f = Fixture::new();
    let policy = f.policy(false, 2);
    let evidence = f.evidence(&policy);
    let mut bad = evidence.clone();
    bad.invitation_intent = bad.device_intent.clone();
    let position = f.engine.journal.startup().unwrap().observed_position;
    assert!(f.apply(f.admission(bad)).is_err());
    assert_eq!(
        f.engine.journal.startup().unwrap().observed_position,
        position
    );
    assert!(f.apply(f.admission(evidence)).is_ok());
}

#[test]
fn approval_policy_requires_exact_owner_signature() {
    let mut f = Fixture::new();
    let policy = f.policy(true, 2);
    let mut evidence = f.evidence(&policy);
    assert!(f.apply(f.admission(evidence.clone())).is_err());
    let approval = WitnessApproval {
        v: 1,
        kind: "witness.approval".into(),
        nonce: record::random_hex::<16>().unwrap(),
        space_id: f.authority.space(),
        stream_id: f.authority.stream(),
        authority_head: f.authority.head_id().unwrap(),
        issuer_credential_id: f.owner.credential.id(),
        intent_id: decode(&evidence.device_intent).unwrap().id(),
        readmission: false,
    };
    evidence.approval = Some(encoded(&signed(&approval, &f.owner.key)));
    assert!(f.apply(f.admission(evidence)).is_ok());
}

#[test]
fn freshness_binds_nonce_and_committed_head_and_clock_failure_seals() {
    let mut f = Fixture::new();
    let nonce = record::random_hex::<32>().unwrap();
    let response = f
        .engine
        .head(
            HeadRequest {
                space_id: f.authority.space(),
                stream_id: f.authority.stream(),
                nonce: nonce.clone(),
            },
            NOW,
        )
        .unwrap();
    let signed = decode(&response).unwrap();
    signed.verify_signature(&f.pin.key().unwrap()).unwrap();
    let body: Freshness = signed.decode().unwrap();
    assert_eq!(body.nonce, nonce);
    assert_eq!(body.authority_head, f.authority.head_id().unwrap());
    assert_eq!(body.expires_at_ms - NOW, 30_000);
    assert!(!f.engine.journal.ready(NOW - 1));
    assert!(!f.engine.journal.ready(NOW));
}

#[test]
fn restart_requires_new_activation_and_independently_known_position() {
    let f = Fixture::new();
    let old = f.engine.journal.startup().unwrap();
    let path = f.directory.path().to_path_buf();
    let pin = f.pin.clone();
    drop(f.engine);
    let mut journal = Journal::open(&path.join("data"), &path.join("key"), pin, NOW).unwrap();
    assert!(!journal.ready(NOW));
    assert!(
        journal
            .activate(
                Activation {
                    startup_nonce: old.startup_nonce,
                    expected_position: old.observed_position.clone(),
                    public_key: old.public_key,
                    key_generation: 1,
                    expires_at_ms: NOW + 1000
                },
                NOW
            )
            .is_err()
    );
    let startup = journal.startup().unwrap();
    assert!(
        journal
            .activate(
                Activation {
                    startup_nonce: startup.startup_nonce,
                    expected_position: Position {
                        sequence: 0,
                        record_id: None
                    },
                    public_key: startup.public_key,
                    key_generation: 1,
                    expires_at_ms: NOW + 1000
                },
                NOW
            )
            .is_err()
    );
    activate(&mut journal, old.observed_position);
    assert!(journal.ready(NOW));
}

#[test]
fn removed_guest_cannot_replay_admission_or_read_new_authority() {
    let mut f = Fixture::new();
    let policy = f.policy(false, 3);
    let evidence = f.evidence(&policy);
    let request = f.admission(evidence);
    let saved = serde_json::to_vec(&request).unwrap();
    f.apply(request).unwrap();
    f.refresh();
    let mut next = f.authority.head().unwrap().clone();
    next.sequence += 1;
    next.previous_config_id = f.authority.head_id();
    next.witness_evidence = None;
    next.nonce = record::random_hex::<16>().unwrap();
    next.action = ConfigAction {
        operation: "member.removed".into(),
        actor_identity: f.owner.credential.identity(),
        request_record_id: None,
    };
    next.members
        .retain(|m| m.identity_id != f.guest.credential.identity());
    let proposal = next.sign(&f.owner.key).unwrap();
    let update = command(
        &f.authority,
        &f.owner,
        Operation::OwnerUpdate {
            proposal: encoded(&proposal),
            credentials: vec![],
        },
    );
    let saved_update = serde_json::to_vec(&update).unwrap();
    let response = f.apply(update).unwrap();
    assert_eq!(
        f.apply(serde_json::from_slice(&saved_update).unwrap())
            .unwrap()
            .receipt,
        response.receipt
    );
    assert!(f.apply(serde_json::from_slice(&saved).unwrap()).is_err());
    f.refresh();
    assert!(
        f.apply(command(&f.authority, &f.guest, Operation::Read))
            .is_err()
    );
}

#[test]
fn registration_replay_cannot_bypass_current_owner_revocation() {
    let mut f = Fixture::new();
    let policy = f.policy(false, 3);
    let evidence = f.evidence(&policy);
    f.apply(f.admission(evidence)).unwrap();
    f.refresh();
    let mut config = f.authority.head().unwrap().clone();
    config.sequence += 1;
    config.previous_config_id = f.authority.head_id();
    config.witness_evidence = None;
    config.nonce = record::random_hex::<16>().unwrap();
    config.action = ConfigAction {
        operation: "replace".into(),
        actor_identity: f.owner.credential.identity(),
        request_record_id: None,
    };
    config
        .members
        .iter_mut()
        .find(|m| m.identity_id == f.guest.credential.identity())
        .unwrap()
        .capabilities = vec![
        Capability::Read,
        Capability::Post,
        Capability::ShareHistory,
        Capability::Manage,
    ];
    let companion_key = SigningKey::from_bytes(&[41; 32]);
    let age = age::x25519::Identity::generate();
    let companion = DeviceCredential::issue_companion(
        &f.owner.credential,
        &f.owner.key,
        &companion_key.verifying_key(),
        &age.to_public(),
    )
    .unwrap();
    let primary = config
        .members
        .iter_mut()
        .find(|m| m.identity_id == f.owner.credential.identity())
        .unwrap();
    primary.credential_ids.push(companion.id());
    primary.credential_ids.sort();
    config
        .owner_credential_ids
        .extend([f.guest.credential.id(), companion.id()]);
    config.owner_credential_ids.sort();
    let proposal = config.sign(&f.owner.key).unwrap();
    f.apply(command(
        &f.authority,
        &f.owner,
        Operation::OwnerUpdate {
            proposal: encoded(&proposal),
            credentials: vec![encoded(companion.record())],
        },
    ))
    .unwrap();
    f.refresh();
    let mut config = f.authority.head().unwrap().clone();
    config.sequence += 1;
    config.previous_config_id = f.authority.head_id();
    config.witness_evidence = None;
    config.nonce = record::random_hex::<16>().unwrap();
    config.controller_credential_id = f.guest.credential.id();
    config.action = ConfigAction {
        operation: "member.removed".into(),
        actor_identity: f.guest.credential.identity(),
        request_record_id: None,
    };
    config
        .members
        .retain(|m| m.identity_id == f.guest.credential.identity());
    config.owner_credential_ids = vec![f.guest.credential.id()];
    let forged = config.sign(&f.guest.key).unwrap();
    let head = f.authority.head_id();
    assert!(
        f.apply(command(
            &f.authority,
            &f.guest,
            Operation::OwnerUpdate {
                proposal: encoded(&forged),
                credentials: vec![],
            }
        ))
        .is_err()
    );
    f.refresh();
    assert_eq!(f.authority.head_id(), head);
    config.members = f.authority.head().unwrap().members.clone();
    config
        .members
        .iter_mut()
        .find(|m| m.identity_id == f.owner.credential.identity())
        .unwrap()
        .credential_ids = vec![companion.id()];
    config.owner_credential_ids = vec![f.guest.credential.id(), companion.id()];
    config.owner_credential_ids.sort();
    let proposal = config.sign(&f.guest.key).unwrap();
    assert!(
        f.apply(command(
            &f.authority,
            &f.guest,
            Operation::OwnerUpdate {
                proposal: encoded(&proposal),
                credentials: vec![],
            },
        ))
        .is_err()
    );
    f.refresh();
    assert_eq!(f.authority.head_id(), head);

    // Device rotation must be authorized by another active creator device,
    // never by a coowner retaining only the creator's identity in the roster.
    let companion_device = Device {
        root: f.owner.root.clone(),
        key: companion_key,
        credential: companion.clone(),
    };
    config.controller_credential_id = companion.id();
    config.action.actor_identity = companion.identity();
    let proposal = config.sign(&companion_device.key).unwrap();
    f.apply(command(
        &f.authority,
        &companion_device,
        Operation::OwnerUpdate {
            proposal: encoded(&proposal),
            credentials: vec![],
        },
    ))
    .unwrap();
    f.refresh();
    let rotated_head = f.authority.head_id();
    let mut reactivation = f.authority.head().unwrap().clone();
    reactivation.sequence += 1;
    reactivation.previous_config_id = rotated_head;
    reactivation.witness_evidence = None;
    reactivation.nonce = record::random_hex::<16>().unwrap();
    reactivation.controller_credential_id = f.guest.credential.id();
    reactivation.action.actor_identity = f.guest.credential.identity();
    let primary = reactivation
        .members
        .iter_mut()
        .find(|m| m.identity_id == companion.identity())
        .unwrap();
    primary.credential_ids.push(f.owner.credential.id());
    primary.credential_ids.sort();
    reactivation
        .owner_credential_ids
        .push(f.owner.credential.id());
    reactivation.owner_credential_ids.sort();
    assert!(
        f.apply(command(
            &f.authority,
            &f.guest,
            Operation::OwnerUpdate {
                proposal: encoded(&reactivation.sign(&f.guest.key).unwrap()),
                credentials: vec![],
            },
        ))
        .is_err()
    );
    f.refresh();
    assert_eq!(f.authority.head_id(), rotated_head);
    assert!(matches!(
        f.apply(serde_json::from_slice(&f.registration).unwrap()),
        Err(Error::Unauthorized)
    ));
}

mod durable;
