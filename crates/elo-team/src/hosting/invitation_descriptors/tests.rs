use super::*;
use ed25519_dalek::SigningKey;
use elo_core::{
    authority::{
        Capability, ChatKind, ConfigAction, Member, Owner, SpaceGenesis, StreamConfig,
        WitnessInvitationPolicy,
    },
    identity::{DeviceCredential, VerifiedCredential},
    witness::{Freshness, HeadRequest, Position, verify_freshness},
};
use std::time::Instant;
const NOW: u64 = 100_000;
const AUDIENCE: &str = "https://api.example.test/spaces/123/invitations/v1";

struct Fixture {
    authority: Authority,
    owners: Vec<(SigningKey, VerifiedCredential)>,
    guest: (SigningKey, VerifiedCredential),
    witness: SigningKey,
    pin: WitnessPin,
    policy: SignedRecord,
    bytes: Vec<u8>,
}
fn signed<T: Serialize>(body: &T, key: &SigningKey) -> SignedRecord {
    SignedRecord::sign(&serde_json::to_vec(body).unwrap(), key).unwrap()
}
fn device(index: u8) -> (SigningKey, SigningKey, VerifiedCredential) {
    let root = SigningKey::from_bytes(&[index; 32]);
    let key = SigningKey::from_bytes(&[index + 10; 32]);
    let age = age::x25519::Identity::generate();
    let credential =
        DeviceCredential::issue(&root, &key.verifying_key(), &age.to_public()).unwrap();
    (root, key, credential)
}
fn fixture() -> Fixture {
    let first = device(1);
    let second = device(2);
    let guest = device(3);
    let witness = SigningKey::from_bytes(&[90; 32]);
    let pin = WitnessPin {
        url: "https://witness.example.test/witness/v1".into(),
        public_key: record::encode_hex(witness.verifying_key().as_bytes()),
        key_generation: 1,
    };
    let mut owners = vec![
        Owner {
            identity_id: first.2.identity(),
            root_public_key: record::encode_hex(first.0.verifying_key().as_bytes()),
        },
        Owner {
            identity_id: second.2.identity(),
            root_public_key: record::encode_hex(second.0.verifying_key().as_bytes()),
        },
    ];
    owners.sort_by_key(|owner| owner.identity_id);
    let genesis = signed(
        &SpaceGenesis {
            v: 4,
            kind: "space.genesis".into(),
            nonce: record::random_hex::<16>().unwrap(),
            issuer_identity: first.2.identity(),
            owners,
            controller_credential_id: first.2.id(),
            witness: Some(pin.clone()),
        },
        &first.1,
    );
    let mut authority = Authority::new(
        genesis.bytes(),
        SpaceId::from_bytes(*genesis.id().as_bytes()),
        &first.0.verifying_key(),
        first.2.clone(),
        StreamId::from_bytes([5; 16]),
    )
    .unwrap();
    authority.add_credential(second.2.clone());
    authority.add_credential(guest.2.clone());
    let mut members: Vec<_> = [&first, &second, &guest]
        .into_iter()
        .enumerate()
        .map(|(index, (root, _, credential))| Member {
            identity_id: credential.identity(),
            identity_type: "HUMAN".into(),
            root_public_key: record::encode_hex(root.verifying_key().as_bytes()),
            capabilities: if index < 2 {
                vec![
                    Capability::Read,
                    Capability::Post,
                    Capability::ShareHistory,
                    Capability::Manage,
                ]
            } else {
                vec![Capability::Read, Capability::Post]
            },
            credential_ids: vec![credential.id()],
            external: false,
        })
        .collect();
    members.sort_by_key(|member| member.identity_id);
    let mut owner_ids = vec![first.2.id(), second.2.id()];
    owner_ids.sort();
    authority
        .apply_config(
            StreamConfig {
                v: 4,
                kind: "stream.config".into(),
                nonce: record::random_hex::<16>().unwrap(),
                space_id: authority.space(),
                stream_id: authority.stream(),
                sequence: 1,
                previous_config_id: None,
                controller_credential_id: first.2.id(),
                members,
                owner_credential_ids: owner_ids,
                action: ConfigAction {
                    operation: "create".into(),
                    actor_identity: first.2.identity(),
                    request_record_id: None,
                },
                chat_kind: Some(ChatKind::Chat),
                recovery: None,
                witness_evidence: None,
            }
            .sign(&first.1)
            .unwrap(),
        )
        .unwrap();
    let policy = signed(
        &WitnessInvitationPolicy {
            v: 1,
            kind: "witness.invitation".into(),
            nonce: record::random_hex::<16>().unwrap(),
            space_id: authority.space(),
            stream_id: authority.stream(),
            authority_head: authority.head_id().unwrap(),
            issuer_credential_id: first.2.id(),
            invitation_public_key: record::encode_hex(
                SigningKey::from_bytes(&[80; 32]).verifying_key().as_bytes(),
            ),
            not_before_ms: NOW - 1,
            expires_at_ms: NOW + 3_600_000,
            require_approval: true,
            max_uses: 10,
            witness_key_generation: 1,
        },
        &first.1,
    );
    let mut bytes = vec![9; 113];
    bytes[0] = 1;
    Fixture {
        authority,
        owners: vec![(first.1, first.2), (second.1, second.2)],
        guest: (guest.1, guest.2),
        witness,
        pin,
        policy,
        bytes,
    }
}
impl Fixture {
    fn command(&self, credential: RecordId) -> UploadCommand {
        UploadCommand {
            v: 1,
            kind: "invitation.descriptor.put".into(),
            nonce: record::random_hex::<32>().unwrap(),
            audience: AUDIENCE.into(),
            space_id: self.authority.space(),
            stream_id: self.authority.stream(),
            authority_head: self.authority.head_id().unwrap(),
            credential_id: credential,
            policy_id: self.policy.id(),
            ciphertext_id: store::ciphertext_id(&self.bytes),
            ciphertext_size: self.bytes.len() as u64,
            ciphertext_expires_at_ms: NOW + 3_600_000,
            issued_at_ms: NOW,
            expires_at_ms: NOW + 60_000,
        }
    }
    fn request(&self, command: &UploadCommand, key: &SigningKey) -> UploadRequest {
        UploadRequest {
            command: STANDARD.encode(signed(command, key).bytes()),
            policy: STANDARD.encode(self.policy.bytes()),
            ciphertext: STANDARD.encode(&self.bytes),
        }
    }
    fn freshness(&self, head: RecordId) -> VerifiedFreshness {
        let request = HeadRequest {
            space_id: self.authority.space(),
            stream_id: self.authority.stream(),
            nonce: record::random_hex::<32>().unwrap(),
        };
        let body = Freshness {
            v: 1,
            kind: "witness.freshness".into(),
            audience: self.pin.url.clone(),
            nonce: request.nonce.clone(),
            space_id: request.space_id,
            stream_id: request.stream_id,
            authority_head: head,
            position: Position {
                sequence: 1,
                record_id: Some(RecordId::from_bytes([33; 32])),
            },
            issued_at_ms: NOW,
            expires_at_ms: NOW + 30_000,
            witness_key_generation: 1,
        };
        verify_freshness(
            &self.pin,
            &request,
            &STANDARD.encode(signed(&body, &self.witness).bytes()),
            Instant::now(),
            NOW,
            None,
        )
        .unwrap()
    }
}

#[test]
fn a_different_current_owner_can_upload_and_exact_retries_stay_immutable() {
    let f = fixture();
    let owner = &f.owners[1];
    let command = f.command(owner.1.id());
    let lease = f.freshness(command.authority_head);
    let upload = prepare(
        f.request(&command, &owner.0),
        &f.authority,
        &f.pin,
        AUDIENCE,
        &lease,
        NOW,
    )
    .unwrap();
    assert_eq!(upload.uploader(), (owner.1.identity(), owner.1.id()));
    assert_eq!(
        upload.policy_issuer(),
        (f.owners[0].1.identity(), f.owners[0].1.id())
    );
    assert_eq!(upload.digest(), command.ciphertext_id);
    assert_eq!(
        upload.ciphertext_expires_at_ms(),
        command.ciphertext_expires_at_ms
    );
    let directory = store::private_test_directory();
    let mut store = Store::open(directory.path()).unwrap();
    assert_eq!(
        upload.commit(&mut store, &f.authority, &lease, NOW),
        Ok(true)
    );
    assert_eq!(
        upload.commit(&mut store, &f.authority, &lease, NOW + 1),
        Ok(false)
    );
    assert_eq!(store.get(upload.digest(), NOW + 2).unwrap(), f.bytes);
}

#[test]
fn valid_member_signatures_do_not_authorize_uploads() {
    let f = fixture();
    let command = f.command(f.guest.1.id());
    let lease = f.freshness(command.authority_head);
    assert!(matches!(
        prepare(
            f.request(&command, &f.guest.0),
            &f.authority,
            &f.pin,
            AUDIENCE,
            &lease,
            NOW
        ),
        Err(Error::Unauthorized)
    ));
    let command = f.command(f.owners[0].1.id());
    assert!(matches!(
        prepare(
            f.request(&command, &f.guest.0),
            &f.authority,
            &f.pin,
            AUDIENCE,
            &lease,
            NOW
        ),
        Err(Error::Unauthorized)
    ));
}

#[test]
fn signed_changes_cannot_escape_scope_policy_hash_size_expiry_or_audience() {
    let f = fixture();
    let base = f.command(f.owners[0].1.id());
    let lease = f.freshness(base.authority_head);
    for change in 0..9 {
        let mut command = base.clone();
        match change {
            0 => command.space_id = SpaceId::from_bytes([88; 32]),
            1 => command.stream_id = StreamId::from_bytes([88; 16]),
            2 => command.authority_head = RecordId::from_bytes([88; 32]),
            3 => command.policy_id = RecordId::from_bytes([88; 32]),
            4 => command.ciphertext_id = ObjectId::from_bytes([88; 32]),
            5 => command.ciphertext_size += 1,
            6 => command.ciphertext_expires_at_ms += 1,
            7 => command.audience = "https://other.example.test/spaces/123/invitations/v1".into(),
            _ => command.expires_at_ms = NOW + 60_001,
        }
        assert!(
            prepare(
                f.request(&command, &f.owners[0].0),
                &f.authority,
                &f.pin,
                AUDIENCE,
                &lease,
                NOW
            )
            .is_err(),
            "mutation {change}"
        );
    }
    let mut request = f.request(&base, &f.owners[0].0);
    let mut changed = f.bytes.clone();
    changed[50] ^= 1;
    request.ciphertext = STANDARD.encode(changed);
    assert!(matches!(
        prepare(request, &f.authority, &f.pin, AUDIENCE, &lease, NOW),
        Err(Error::Invalid)
    ));
}

#[test]
fn fresh_exact_head_and_configured_pin_are_required_again_at_commit() {
    let f = fixture();
    let command = f.command(f.owners[0].1.id());
    let lease = f.freshness(command.authority_head);
    let wrong_head = f.freshness(RecordId::from_bytes([44; 32]));
    assert!(matches!(
        prepare(
            f.request(&command, &f.owners[0].0),
            &f.authority,
            &f.pin,
            AUDIENCE,
            &wrong_head,
            NOW
        ),
        Err(Error::Unauthorized)
    ));
    let mut wrong_pin = f.pin.clone();
    wrong_pin.public_key =
        record::encode_hex(SigningKey::from_bytes(&[89; 32]).verifying_key().as_bytes());
    assert!(matches!(
        prepare(
            f.request(&command, &f.owners[0].0),
            &f.authority,
            &wrong_pin,
            AUDIENCE,
            &lease,
            NOW
        ),
        Err(Error::Unauthorized)
    ));
    let upload = prepare(
        f.request(&command, &f.owners[0].0),
        &f.authority,
        &f.pin,
        AUDIENCE,
        &lease,
        NOW,
    )
    .unwrap();
    let directory = store::private_test_directory();
    let mut store = Store::open(directory.path()).unwrap();
    assert_eq!(
        upload.commit(&mut store, &f.authority, &wrong_head, NOW),
        Err(Error::Unauthorized)
    );
    assert_eq!(
        upload.commit(&mut store, &f.authority, &lease, NOW + 30_000),
        Err(Error::Unauthorized)
    );
    assert_eq!(
        store.get(upload.digest(), NOW + 30_000),
        Err(Error::Missing)
    );
}

#[tokio::test]
async fn request_schema_rejects_seed_or_full_link_fields() {
    let ingress = Ingress::new();
    let body = serde_json::json!({"command":"synthetic","policy":"synthetic","ciphertext":"synthetic","seed":"synthetic forbidden secret"});
    let request = axum::extract::Request::builder()
        .header("content-type", "application/json")
        .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    assert!(matches!(
        ingress
            .receive(
                "127.0.0.1".parse().unwrap(),
                ObjectId::from_bytes([1; 32]),
                request
            )
            .await,
        Err(Error::Invalid)
    ));
}
