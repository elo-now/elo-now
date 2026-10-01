use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::SigningKey;
use elo_core::{
    authority::{
        Authority, Capability, ConfigAction, ConfigAdmission, ControllerRecovery, Member, Owner,
        SpaceGenesis, StreamConfig,
    },
    identity::{DeviceCredential, VerifiedCredential},
    ids::{RecordId, StreamId},
    record::{SignedRecord, encode_hex, random_hex},
};
use std::io::{Read, Write};

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
struct Fixture {
    root: SigningKey,
    first: Device,
    second: Device,
    unadmitted: Device,
    foreign: Device,
    authority: Authority,
}
fn fixture(version: u64, admit_second: bool) -> Fixture {
    let root = SigningKey::from_bytes(&[10; 32]);
    let first = device(&root, 11);
    let mut second = device(&root, 12);
    second.credential = DeviceCredential::issue_companion(
        &first.credential,
        &first.key,
        &second.key.verifying_key(),
        &second.age.to_public(),
    )
    .unwrap();
    let unadmitted = device(&root, 13);
    let foreign = device(&SigningKey::from_bytes(&[20; 32]), 21);
    let genesis = SpaceGenesis {
        v: version,
        kind: "space.genesis".into(),
        nonce: random_hex::<16>().unwrap(),
        issuer_identity: first.credential.identity(),
        owners: vec![Owner {
            identity_id: first.credential.identity(),
            root_public_key: encode_hex(root.verifying_key().as_bytes()),
        }],
        controller_credential_id: first.credential.id(),
    };
    let genesis = SignedRecord::sign(
        &serde_json::to_vec(&genesis).unwrap(),
        if version == 1 { &root } else { &first.key },
    )
    .unwrap();
    let mut authority = Authority::new(
        genesis.bytes(),
        genesis.id().to_string().parse().unwrap(),
        &root.verifying_key(),
        first.credential.clone(),
        StreamId::from_bytes([2; 16]),
    )
    .unwrap();
    for device in [&second, &unadmitted, &foreign] {
        authority.add_credential(device.credential.clone());
    }
    let mut ids = vec![first.credential.id()];
    if admit_second {
        ids.push(second.credential.id());
    }
    ids.sort();
    let config = StreamConfig {
        v: version,
        kind: "stream.config".into(),
        nonce: random_hex::<16>().unwrap(),
        space_id: authority.space(),
        stream_id: authority.stream(),
        sequence: 1,
        previous_config_id: None,
        controller_credential_id: first.credential.id(),
        members: vec![Member {
            identity_id: first.credential.identity(),
            identity_type: "HUMAN".into(),
            root_public_key: encode_hex(root.verifying_key().as_bytes()),
            capabilities: vec![
                Capability::Read,
                Capability::Post,
                Capability::ShareHistory,
                Capability::Manage,
            ],
            credential_ids: ids.clone(),
            external: false,
        }],
        owner_credential_ids: ids,
        action: ConfigAction {
            operation: "create".into(),
            actor_identity: first.credential.identity(),
            request_record_id: None,
        },
        chat_kind: None,
        recovery: None,
    };
    authority
        .apply_config(config.sign(&first.key).unwrap())
        .unwrap();
    Fixture {
        root,
        first,
        second,
        unadmitted,
        foreign,
        authority,
    }
}
fn next(authority: &Authority, signer: &Device) -> StreamConfig {
    let mut config = authority.head().unwrap().clone();
    config.sequence += 1;
    config.previous_config_id = authority.head_id();
    config.nonce = random_hex::<16>().unwrap();
    config.controller_credential_id = signer.credential.id();
    config.action = ConfigAction {
        operation: "replace".into(),
        actor_identity: signer.credential.identity(),
        request_record_id: None,
    };
    config
}
fn owner_devices(config: &mut StreamConfig, mut ids: Vec<RecordId>) {
    ids.sort();
    config.members[0].credential_ids = ids.clone();
    config.owner_credential_ids = ids;
}

#[test]
fn device_signed_genesis_binds_the_exact_initial_device_and_pinned_root() {
    let f = fixture(2, true);
    let original = f.authority.genesis();
    let open = |signed: &SignedRecord, initial: &Device, root: &SigningKey| {
        Authority::new(
            signed.bytes(),
            signed.id().to_string().parse().unwrap(),
            &root.verifying_key(),
            initial.credential.clone(),
            f.authority.stream(),
        )
    };
    assert!(open(original, &f.first, &f.root).is_ok());
    assert!(open(original, &f.second, &f.root).is_err());
    assert!(open(original, &f.first, &SigningKey::from_bytes(&[20; 32])).is_err());
    for key in [&f.root, &f.second.key, &f.foreign.key] {
        let forged =
            SignedRecord::sign(&serde_json::to_vec(original.body()).unwrap(), key).unwrap();
        assert!(open(&forged, &f.first, &f.root).is_err());
    }
    let mut fresh = open(original, &f.first, &f.root).unwrap();
    fresh.add_credential(f.second.credential.clone());
    let mut initial = f.authority.head().unwrap().clone();
    initial.controller_credential_id = f.second.credential.id();
    assert!(
        fresh
            .apply_config(initial.sign(&f.second.key).unwrap())
            .is_err()
    );
    assert!(fresh.head_id().is_none());
    // The framing version exception is narrow: unrelated version 2 records stay rejected.
    let invalid = serde_json::json!({"v":2,"kind":"stream.checkpoint"});
    assert!(SignedRecord::sign(&serde_json::to_vec(&invalid).unwrap(), &f.first.key).is_err());
}

#[test]
fn independent_owner_devices_alternate_and_the_survivor_revokes_the_initial_device() {
    let mut f = fixture(2, true);
    assert!(f.authority.is_owner_managed());
    for device in [&f.second, &f.first, &f.second] {
        assert!(f.authority.can_manage(device.credential.id()));
        let config = next(&f.authority, device);
        assert_eq!(
            f.authority
                .apply_config(config.sign(&device.key).unwrap())
                .unwrap(),
            ConfigAdmission::Applied
        );
        assert_eq!(f.authority.controller().id(), device.credential.id());
        assert!(f.authority.controller_ready_with(&[]));
    }
    let mut removal = next(&f.authority, &f.second);
    owner_devices(&mut removal, vec![f.second.credential.id()]);
    removal.action.operation = "device.removed".into();
    f.authority
        .apply_config(removal.sign(&f.second.key).unwrap())
        .unwrap();
    assert!(!f.authority.can_manage(f.first.credential.id()));
    assert!(f.authority.can_manage(f.second.credential.id()));
    let head = f.authority.head_id();
    for unauthorized in [&f.first, &f.unadmitted] {
        let mut forged = next(&f.authority, unauthorized);
        // Same identity and a self-added credential do not grant previous-head authority.
        owner_devices(
            &mut forged,
            vec![f.second.credential.id(), unauthorized.credential.id()],
        );
        assert!(
            f.authority
                .apply_config(forged.sign(&unauthorized.key).unwrap())
                .is_err()
        );
        assert_eq!(f.authority.head_id(), head);
    }
    f.authority
        .apply_config(next(&f.authority, &f.second).sign(&f.second.key).unwrap())
        .unwrap();
}

#[test]
fn device_admission_requires_an_existing_owner_signature_and_cannot_promote_a_foreign_identity() {
    let mut f = fixture(2, false);
    let mut admission = next(&f.authority, &f.second);
    owner_devices(
        &mut admission,
        vec![f.first.credential.id(), f.second.credential.id()],
    );
    assert!(
        f.authority
            .apply_config(admission.sign(&f.second.key).unwrap())
            .is_err()
    );
    admission.controller_credential_id = f.first.credential.id();
    f.authority
        .apply_config(admission.sign(&f.first.key).unwrap())
        .unwrap();
    f.authority
        .apply_config(next(&f.authority, &f.second).sign(&f.second.key).unwrap())
        .unwrap();
    let mut foreign = next(&f.authority, &f.foreign);
    foreign.members.push(Member {
        identity_id: f.foreign.credential.identity(),
        identity_type: "HUMAN".into(),
        root_public_key: f.foreign.credential.record().body()["root_public_key"]
            .as_str()
            .unwrap()
            .into(),
        capabilities: vec![
            Capability::Read,
            Capability::Post,
            Capability::ShareHistory,
            Capability::Manage,
        ],
        credential_ids: vec![f.foreign.credential.id()],
        external: true,
    });
    foreign.members.sort_by_key(|m| m.identity_id);
    foreign.owner_credential_ids.push(f.foreign.credential.id());
    foreign.owner_credential_ids.sort();
    assert!(
        f.authority
            .apply_config(foreign.sign(&f.foreign.key).unwrap())
            .is_err()
    );
    assert!(!f.authority.can_manage(f.foreign.credential.id()));
    let mut wrong_actor = next(&f.authority, &f.second);
    wrong_actor.action.actor_identity = f.foreign.credential.identity();
    assert!(
        f.authority
            .apply_config(wrong_actor.sign(&f.second.key).unwrap())
            .is_err()
    );
}

#[test]
fn an_admitted_owner_can_delegate_to_another_identity_and_transfer_away_the_founder() {
    let mut f = fixture(2, true);
    let mut promotion = next(&f.authority, &f.first);
    promotion.members.push(Member {
        identity_id: f.foreign.credential.identity(),
        identity_type: "HUMAN".into(),
        root_public_key: f.foreign.credential.record().body()["root_public_key"]
            .as_str()
            .unwrap()
            .into(),
        capabilities: vec![
            Capability::Read,
            Capability::Post,
            Capability::ShareHistory,
            Capability::Manage,
        ],
        credential_ids: vec![f.foreign.credential.id()],
        external: true,
    });
    promotion.members.sort_by_key(|m| m.identity_id);
    promotion
        .owner_credential_ids
        .push(f.foreign.credential.id());
    promotion.owner_credential_ids.sort();
    f.authority
        .apply_config(promotion.sign(&f.first.key).unwrap())
        .unwrap();
    assert!(f.authority.can_manage(f.foreign.credential.id()));
    // The founder may authorize its own removal; controller records that signer,
    // while only the newly delegated owner can manage the resulting head.
    let mut transfer = next(&f.authority, &f.first);
    transfer
        .members
        .retain(|m| m.identity_id == f.foreign.credential.identity());
    transfer.owner_credential_ids = vec![f.foreign.credential.id()];
    f.authority
        .apply_config(transfer.sign(&f.first.key).unwrap())
        .unwrap();
    assert_eq!(f.authority.controller().id(), f.first.credential.id());
    assert!(!f.authority.can_manage(f.first.credential.id()));
    assert!(!f.authority.can_manage(f.second.credential.id()));
    assert!(f.authority.can_manage(f.foreign.credential.id()));
    assert!(
        f.authority
            .apply_config(next(&f.authority, &f.first).sign(&f.first.key).unwrap())
            .is_err()
    );
    f.authority
        .apply_config(next(&f.authority, &f.foreign).sign(&f.foreign.key).unwrap())
        .unwrap();
    let proof = f.authority.call_proof_signed(&f.foreign.key).unwrap();
    let verified = proof
        .verify(f.authority.space(), f.authority.stream())
        .unwrap();
    assert!(verified.can_manage(f.foreign.credential.id()));
    assert!(!verified.can_manage(f.first.credential.id()));
    let mut no_owner = next(&f.authority, &f.foreign);
    no_owner.members[0].capabilities = vec![Capability::Read, Capability::Post];
    no_owner.owner_credential_ids.clear();
    assert!(
        f.authority
            .apply_config(no_owner.sign(&f.foreign.key).unwrap())
            .is_err()
    );
    let mut incomplete = next(&f.authority, &f.foreign);
    incomplete.members[0].capabilities =
        vec![Capability::Read, Capability::Post, Capability::Manage];
    assert!(
        f.authority
            .apply_config(incomplete.sign(&f.foreign.key).unwrap())
            .is_err()
    );
}

#[test]
fn stale_owner_updates_remain_fork_evidence_instead_of_replacing_the_head() {
    let mut f = fixture(2, true);
    let stale = next(&f.authority, &f.first).sign(&f.first.key).unwrap();
    let mut removal = next(&f.authority, &f.second);
    owner_devices(&mut removal, vec![f.second.credential.id()]);
    f.authority
        .apply_config(removal.sign(&f.second.key).unwrap())
        .unwrap();
    let head = f.authority.head_id();
    assert_eq!(
        f.authority.apply_config(stale).unwrap(),
        ConfigAdmission::Forked
    );
    assert_eq!(f.authority.head_id(), head);
    assert!(!f.authority.can_manage(f.second.credential.id()));
    assert!(!f.authority.controller_ready_with(&[]));
    assert!(f.authority.call_proof_signed(&f.second.key).is_err());
    let sealed = f
        .authority
        .seal_snapshot(&f.second.age.to_public())
        .unwrap();
    let restored = Authority::open_snapshot(
        &sealed,
        &f.second.age,
        f.authority.space(),
        &f.root.verifying_key(),
        f.authority.stream(),
    )
    .unwrap();
    assert!(restored.is_forked());
}

#[test]
fn versions_cannot_be_upgraded_or_downgraded_inside_a_configuration_chain() {
    for version in [1, 2] {
        let mut f = fixture(version, true);
        assert_eq!(f.authority.is_owner_managed(), version == 2);
        assert_eq!(
            f.authority.can_manage(f.second.credential.id()),
            version == 2
        );
        let mut changed = next(&f.authority, &f.first);
        changed.v = 3 - version;
        assert!(
            f.authority
                .apply_config(changed.sign(&f.first.key).unwrap())
                .is_err()
        );
        if version == 1 {
            assert!(
                f.authority
                    .apply_config(next(&f.authority, &f.second).sign(&f.second.key).unwrap())
                    .is_err()
            );
        }
    }
}

#[test]
fn full_proofs_and_encrypted_snapshots_verify_alternating_signers_without_checkpoint_trust() {
    let mut f = fixture(2, true);
    let first = f.authority.head_id().unwrap();
    f.authority
        .apply_config(next(&f.authority, &f.second).sign(&f.second.key).unwrap())
        .unwrap();
    let proof = f.authority.call_proof_signed(&f.second.key).unwrap();
    assert_eq!(
        proof.v, 1,
        "proof envelope version is separate from genesis/config version"
    );
    assert!(proof.checkpoint.is_none());
    assert_eq!(proof.configs.len(), 2);
    let proof: elo_core::authority::CallAuthorityProof =
        serde_json::from_slice(&serde_json::to_vec(&proof).unwrap()).unwrap();
    let verified = proof
        .verify(f.authority.space(), f.authority.stream())
        .unwrap();
    assert_eq!(verified.head_id(), f.authority.head_id());
    assert!(verified.can_manage(f.first.credential.id()));
    assert!(verified.proves_config_at(first, 1));
    let mut missing = proof.clone();
    missing.configs.remove(0);
    assert!(
        missing
            .verify(f.authority.space(), f.authority.stream())
            .is_err()
    );
    let body = serde_json::json!({
        "v":1,"kind":"stream.checkpoint","space_id":f.authority.space(),"stream_id":f.authority.stream(),
        "controller_credential_id":f.second.credential.id(),"config_id":f.authority.head_id(),"sequence":2,
        "ancestry":[first,f.authority.head_id().unwrap()],"recovery":[],
    });
    let checkpoint =
        SignedRecord::sign(&serde_json::to_vec(&body).unwrap(), &f.second.key).unwrap();
    missing.v = 2;
    missing.checkpoint = Some(STANDARD.encode(checkpoint.bytes()));
    assert!(
        missing
            .verify(f.authority.space(), f.authority.stream())
            .is_err()
    );
    let sealed = f
        .authority
        .seal_snapshot_signed(&f.first.age.to_public(), &f.second.key)
        .unwrap();
    let restored = Authority::open_snapshot(
        &sealed,
        &f.first.age,
        f.authority.space(),
        &f.root.verifying_key(),
        f.authority.stream(),
    )
    .unwrap();
    assert_eq!(restored.head_id(), f.authority.head_id());
    assert!(restored.can_manage(f.first.credential.id()));
    let decryptor = age::Decryptor::new(sealed.as_slice()).unwrap();
    let mut reader = decryptor
        .decrypt(std::iter::once(&f.first.age as &dyn age::Identity))
        .unwrap();
    let mut plain = Vec::new();
    reader.read_to_end(&mut plain).unwrap();
    let mut body: serde_json::Value = serde_json::from_slice(&plain).unwrap();
    body["checkpoint"] = STANDARD.encode(checkpoint.bytes()).into();
    let recipient = f.first.age.to_public();
    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
            .unwrap();
    let mut tampered = Vec::new();
    let mut writer = encryptor.wrap_output(&mut tampered).unwrap();
    writer
        .write_all(&serde_json::to_vec(&body).unwrap())
        .unwrap();
    writer.finish().unwrap();
    assert!(
        Authority::open_snapshot(
            &tampered,
            &f.first.age,
            f.authority.space(),
            &f.root.verifying_key(),
            f.authority.stream()
        )
        .is_err()
    );
}

#[test]
fn legacy_recovery_cannot_bypass_version_two_owner_admission() {
    let mut f = fixture(2, true);
    assert!(
        f.authority
            .sign_recovery(&f.unadmitted.credential, &f.root)
            .is_err()
    );
    assert!(
        f.authority
            .verify_controller_export(&[], &f.first.credential)
            .is_err()
    );
    let certificate = ControllerRecovery {
        v: 1,
        kind: "space.controller.recovered".into(),
        nonce: random_hex::<16>().unwrap(),
        space_id: f.authority.space(),
        sequence: 1,
        previous_recovery_id: None,
        previous_controller_credential_id: f.first.credential.id(),
        controller_credential_id: f.unadmitted.credential.id(),
    };
    let signed = SignedRecord::sign(&serde_json::to_vec(&certificate).unwrap(), &f.root).unwrap();
    assert!(
        f.authority
            .prepare_recovery(&signed, &f.unadmitted.key)
            .is_err()
    );
    let mut recovery = next(&f.authority, &f.unadmitted);
    owner_devices(&mut recovery, vec![f.unadmitted.credential.id()]);
    recovery.recovery = Some(STANDARD.encode(signed.bytes()));
    recovery.action.operation = "controller.recovered".into();
    recovery.action.request_record_id = Some(signed.id());
    assert!(
        f.authority
            .apply_config(recovery.sign(&f.unadmitted.key).unwrap())
            .is_err()
    );
    let mut renamed = next(&f.authority, &f.first);
    renamed.recovery = Some(STANDARD.encode(signed.bytes()));
    assert!(
        f.authority
            .apply_config(renamed.sign(&f.first.key).unwrap())
            .is_err()
    );
}
