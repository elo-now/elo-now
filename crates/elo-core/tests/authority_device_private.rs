use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::SigningKey;
use elo_core::{
    authority::{
        Authority, Capability, ChatKind, ConfigAction, ConfigAdmission, Member, Owner,
        SpaceGenesis, StreamConfig,
    },
    identity::{DeviceCredential, VerifiedCredential},
    ids::StreamId,
    record::{SignedRecord, encode_hex, random_hex},
};

struct Device {
    key: SigningKey,
    age: age::x25519::Identity,
    credential: VerifiedCredential,
}

fn device(root: &SigningKey, seed: u8) -> Device {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let age = age::x25519::Identity::generate();
    let credential = DeviceCredential::issue(root, &key.verifying_key(), &age.to_public()).unwrap();
    Device {
        key,
        age,
        credential,
    }
}

fn genesis(root: &SigningKey, owner: &Device) -> SpaceGenesis {
    SpaceGenesis {
        witness: None,
        v: 3,
        kind: "space.genesis".into(),
        nonce: random_hex::<16>().unwrap(),
        issuer_identity: owner.credential.identity(),
        owners: vec![Owner {
            identity_id: owner.credential.identity(),
            root_public_key: encode_hex(root.verifying_key().as_bytes()),
        }],
        controller_credential_id: owner.credential.id(),
    }
}

fn open_genesis(
    genesis: &SpaceGenesis,
    signer: &SigningKey,
    root: &SigningKey,
    owner: &Device,
) -> elo_core::record::Result<Authority> {
    let signed = SignedRecord::sign(&serde_json::to_vec(genesis).unwrap(), signer)?;
    Authority::new(
        signed.bytes(),
        signed.id().to_string().parse().unwrap(),
        &root.verifying_key(),
        owner.credential.clone(),
        StreamId::from_bytes([31; 16]),
    )
}

fn fixture() -> (SigningKey, Device, Authority) {
    let root = SigningKey::from_bytes(&[30; 32]);
    let owner = device(&root, 31);
    let mut authority = open_genesis(&genesis(&root, &owner), &owner.key, &root, &owner).unwrap();
    let config = StreamConfig {
        witness_evidence: None,
        v: 3,
        kind: "stream.config".into(),
        nonce: random_hex::<16>().unwrap(),
        space_id: authority.space(),
        stream_id: authority.stream(),
        sequence: 1,
        previous_config_id: None,
        controller_credential_id: owner.credential.id(),
        members: vec![Member {
            identity_id: owner.credential.identity(),
            identity_type: "HUMAN".into(),
            root_public_key: encode_hex(root.verifying_key().as_bytes()),
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
        chat_kind: Some(ChatKind::Direct),
        recovery: None,
    };
    authority
        .apply_config(config.sign(&owner.key).unwrap())
        .unwrap();
    (root, owner, authority)
}

fn next_config(authority: &Authority) -> StreamConfig {
    let mut config = authority.head().unwrap().clone();
    config.sequence += 1;
    config.previous_config_id = authority.head_id();
    config.nonce = random_hex::<16>().unwrap();
    config.action.operation = "replace".into();
    config.action.request_record_id = None;
    config.recovery = None;
    config
}

#[test]
fn private_genesis_requires_the_exact_device_signature_and_one_matching_owner() {
    let root = SigningKey::from_bytes(&[30; 32]);
    let owner = device(&root, 31);
    let other_device = device(&root, 32);
    let foreign_root = SigningKey::from_bytes(&[40; 32]);
    let foreign = device(&foreign_root, 41);
    let valid = genesis(&root, &owner);

    assert!(open_genesis(&valid, &owner.key, &root, &owner).is_ok());
    assert!(open_genesis(&valid, &root, &root, &owner).is_err());
    assert!(open_genesis(&valid, &other_device.key, &root, &owner).is_err());
    assert!(open_genesis(&valid, &foreign.key, &root, &owner).is_err());
    assert!(open_genesis(&valid, &owner.key, &foreign_root, &owner).is_err());
    assert!(open_genesis(&valid, &owner.key, &root, &other_device).is_err());

    let mut multiple_owners = valid.clone();
    multiple_owners.owners.push(Owner {
        identity_id: foreign.credential.identity(),
        root_public_key: encode_hex(foreign_root.verifying_key().as_bytes()),
    });
    multiple_owners
        .owners
        .sort_by_key(|entry| entry.identity_id);
    assert!(open_genesis(&multiple_owners, &owner.key, &root, &owner).is_err());

    let mut wrong_owner = valid.clone();
    wrong_owner.owners = vec![Owner {
        identity_id: foreign.credential.identity(),
        root_public_key: encode_hex(foreign_root.verifying_key().as_bytes()),
    }];
    assert!(open_genesis(&wrong_owner, &owner.key, &root, &owner).is_err());
    let mut wrong_issuer = valid;
    wrong_issuer.issuer_identity = foreign.credential.identity();
    assert!(open_genesis(&wrong_issuer, &owner.key, &root, &owner).is_err());
}

#[test]
fn private_v3_keeps_one_controller_even_when_another_owner_device_is_admitted() {
    let (root, owner, mut authority) = fixture();
    let second = device(&root, 32);
    authority.add_credential(second.credential.clone());
    let mut config = next_config(&authority);
    config.members[0]
        .credential_ids
        .push(second.credential.id());
    config.members[0].credential_ids.sort();
    config.owner_credential_ids = config.members[0].credential_ids.clone();
    assert_eq!(
        authority
            .apply_config(config.sign(&owner.key).unwrap())
            .unwrap(),
        ConfigAdmission::Applied
    );
    assert!(!authority.is_owner_managed());
    assert!(authority.can_manage(owner.credential.id()));
    assert!(!authority.can_manage(second.credential.id()));

    let next = next_config(&authority);
    assert!(
        authority
            .clone()
            .apply_config(next.sign(&root).unwrap())
            .is_err()
    );
    assert!(
        authority
            .clone()
            .apply_config(next.sign(&second.key).unwrap())
            .is_err()
    );
    let mut substituted = next.clone();
    substituted.controller_credential_id = second.credential.id();
    assert!(
        authority
            .clone()
            .apply_config(substituted.sign(&second.key).unwrap())
            .is_err()
    );
    let mut downgraded = next;
    downgraded.v = 1;
    assert!(
        authority
            .clone()
            .apply_config(downgraded.sign(&owner.key).unwrap())
            .is_err()
    );
}

#[test]
fn private_v3_snapshot_and_checkpoint_verify_scope_history_and_signatures() {
    let (root, owner, mut authority) = fixture();
    let first = authority.head_id().unwrap();
    let next = next_config(&authority);
    authority
        .apply_config(next.sign(&owner.key).unwrap())
        .unwrap();
    let snapshot = authority
        .seal_snapshot_signed(&owner.age.to_public(), &owner.key)
        .unwrap();
    let reopened = Authority::open_snapshot(
        &snapshot,
        &owner.age,
        authority.space(),
        &root.verifying_key(),
        authority.stream(),
    )
    .unwrap();
    assert_eq!(reopened.head_id(), authority.head_id());
    assert_eq!(reopened.head().unwrap().v, 3);
    assert!(!reopened.is_owner_managed());

    let proof = authority.call_proof_signed(&owner.key).unwrap();
    assert_eq!(proof.v, 2, "the compact proof has its own envelope version");
    let compact = proof.verify(authority.space(), authority.stream()).unwrap();
    assert_eq!(compact.head_id(), authority.head_id());
    assert!(compact.proves_config_ancestor(first));
    assert!(
        proof
            .verify(authority.space(), StreamId::from_bytes([99; 16]))
            .is_err()
    );

    let checkpoint =
        SignedRecord::parse(&STANDARD.decode(proof.checkpoint.as_ref().unwrap()).unwrap()).unwrap();
    let mut changed = checkpoint.body().clone();
    changed["config_id"] = "aa".repeat(32).into();
    let mut bad = proof.clone();
    bad.checkpoint = Some(
        STANDARD.encode(
            SignedRecord::sign(&serde_json::to_vec(&changed).unwrap(), &owner.key)
                .unwrap()
                .bytes(),
        ),
    );
    assert!(bad.verify(authority.space(), authority.stream()).is_err());
    let foreign = device(&SigningKey::from_bytes(&[40; 32]), 41);
    let mut wrong_signer = proof;
    wrong_signer.checkpoint = Some(
        STANDARD.encode(
            SignedRecord::sign(
                &serde_json::to_vec(checkpoint.body()).unwrap(),
                &foreign.key,
            )
            .unwrap()
            .bytes(),
        ),
    );
    assert!(
        wrong_signer
            .verify(authority.space(), authority.stream())
            .is_err()
    );
}

#[test]
fn private_v3_recovery_still_requires_the_identity_root_and_retires_the_old_signer() {
    let (root, owner, mut authority) = fixture();
    let fresh = device(&root, 33);
    let wrong_root = SigningKey::from_bytes(&[40; 32]);
    authority.add_credential(fresh.credential.clone());
    assert!(
        authority
            .sign_recovery(&fresh.credential, &wrong_root)
            .is_err()
    );
    let certificate = authority.sign_recovery(&fresh.credential, &root).unwrap();
    let mut forged_body = certificate.body().clone();
    forged_body["nonce"] = random_hex::<16>().unwrap().into();
    let forged =
        SignedRecord::sign(&serde_json::to_vec(&forged_body).unwrap(), &owner.key).unwrap();
    assert!(
        authority
            .verify_controller_export(&[forged], &fresh.credential)
            .is_err()
    );

    let recovery = authority
        .prepare_recovery(&certificate, &fresh.key)
        .unwrap();
    assert_eq!(
        authority.apply_config(recovery).unwrap(),
        ConfigAdmission::Applied
    );
    assert_eq!(authority.head().unwrap().v, 3);
    assert_eq!(authority.controller().id(), fresh.credential.id());
    assert!(!authority.can_manage(owner.credential.id()));
    assert!(authority.can_manage(fresh.credential.id()));
    authority
        .verify_controller_export(std::slice::from_ref(&certificate), &fresh.credential)
        .unwrap();

    let compact = authority
        .call_proof_signed(&fresh.key)
        .unwrap()
        .verify(authority.space(), authority.stream())
        .unwrap();
    assert_eq!(compact.recovery_id(), Some(certificate.id()));
    assert_eq!(compact.controller().id(), fresh.credential.id());
    let mut stale = next_config(&authority);
    stale.controller_credential_id = owner.credential.id();
    assert!(
        authority
            .apply_config(stale.sign(&owner.key).unwrap())
            .is_err()
    );
}

#[test]
fn private_authority_version_does_not_enable_other_v3_record_kinds() {
    let key = SigningKey::from_bytes(&[31; 32]);
    for kind in [
        "device.credential",
        "device.revoked",
        "space.create",
        "stream.checkpoint",
        "space.controller.recovered",
        "chat.message",
    ] {
        let body = serde_json::json!({"v":3,"kind":kind});
        assert!(
            SignedRecord::sign(&serde_json::to_vec(&body).unwrap(), &key).is_err(),
            "{kind}"
        );
    }
}
