mod common {
    pub mod authority_fixture;
}
use base64::{Engine, engine::general_purpose::STANDARD};
use common::authority_fixture::setup;
use elo_core::{authority::ConfigAdmission, record::random_hex};

#[test]
fn checkpoint_binds_scope_head_members_and_preserves_local_history() {
    let (owner, reader, mut authority, messages) = setup();
    for _ in 0..120 {
        let mut next = authority.head().unwrap().clone();
        next.sequence += 1;
        next.previous_config_id = authority.head_id();
        next.nonce = random_hex::<16>().unwrap();
        authority
            .apply_config(next.sign(&owner.key).unwrap())
            .unwrap();
    }
    let full = authority.call_proof().unwrap();
    let proof = authority.call_proof_signed(&owner.key).unwrap();
    assert_eq!(proof.v, 2);
    assert!(
        serde_json::to_vec(&proof).unwrap().len() * 4 < serde_json::to_vec(&full).unwrap().len()
    );
    let compact = proof.verify(authority.space(), authority.stream()).unwrap();
    assert_eq!(compact.head_id(), authority.head_id());
    assert_eq!(
        compact.head().unwrap().members,
        authority.head().unwrap().members
    );
    let first = messages[0].chat().unwrap().config_id;
    assert!(compact.proves_config_ancestor(first));
    assert!(
        compact.config(first).is_err(),
        "compact state must not claim historical membership"
    );
    authority.verify_historical(&messages[0]).unwrap();
    assert!(compact.seal_snapshot(&reader.age.to_public()).is_err());
    let mut compact = compact;
    assert!(
        compact
            .apply_config(
                authority
                    .config_record(authority.head_id().unwrap())
                    .unwrap()
                    .clone()
            )
            .is_err()
    );
    assert!(
        proof
            .verify(
                authority.space(),
                elo_core::ids::StreamId::from_bytes([4; 16])
            )
            .is_err()
    );
    assert_eq!(authority.call_proof_signed(&reader.key).unwrap().v, 1);
}

#[test]
fn checkpoint_rejects_tampering_substitution_duplicates_and_unknown_versions() {
    let (owner, reader, authority, _) = setup();
    let proof = authority.call_proof_signed(&owner.key).unwrap();
    let record = elo_core::record::SignedRecord::parse(
        &STANDARD.decode(proof.checkpoint.as_ref().unwrap()).unwrap(),
    )
    .unwrap();
    for edit in 0..6 {
        let mut body = record.body().clone();
        match edit {
            0 => body["sequence"] = 1.into(),
            1 => body["config_id"] = "ab".repeat(32).into(),
            2 => body["stream_id"] = "ab".repeat(16).into(),
            3 => body["ancestry"][0] = body["ancestry"][1].clone(),
            4 => body["v"] = 2.into(),
            _ => {}
        }
        let key = if edit == 5 { &reader.key } else { &owner.key };
        let signed = elo_core::record::SignedRecord::sign(&serde_json::to_vec(&body).unwrap(), key);
        if edit == 4 {
            assert!(signed.is_err());
            continue;
        }
        let changed = signed.unwrap();
        let mut bad = proof.clone();
        bad.checkpoint = Some(STANDARD.encode(changed.bytes()));
        assert!(
            bad.verify(authority.space(), authority.stream()).is_err(),
            "case {edit}"
        );
    }
    let mut bad = proof;
    bad.checkpoint = None;
    assert!(bad.verify(authority.space(), authority.stream()).is_err());
}

#[test]
fn checkpoint_refuses_known_fork_and_uses_root_authorized_recovery_generation() {
    let (owner, _, mut authority, _) = setup();
    let mut branch = authority.head().unwrap().clone();
    branch.nonce = random_hex::<16>().unwrap();
    let fork = branch.sign(&owner.key).unwrap();
    let fresh = elo_core::identity::generate_signing_key().unwrap();
    let age = age::x25519::Identity::generate();
    let credential = elo_core::identity::DeviceCredential::issue(
        &owner.root,
        &fresh.verifying_key(),
        &age.to_public(),
    )
    .unwrap();
    authority.add_credential(credential.clone());
    let cert = authority.sign_recovery(&credential, &owner.root).unwrap();
    let next = authority.prepare_recovery(&cert, &fresh).unwrap();
    let mut recovered = authority.clone();
    recovered.apply_config(next).unwrap();
    let proof = recovered.call_proof_signed(&fresh).unwrap();
    let compact = proof.verify(recovered.space(), recovered.stream()).unwrap();
    assert_eq!(compact.recovery_id(), Some(cert.id()));
    assert_eq!(compact.controller().id(), credential.id());
    assert_eq!(
        authority.apply_config(fork).unwrap(),
        ConfigAdmission::Forked
    );
    assert!(authority.call_proof_signed(&owner.key).is_err());
}

#[tokio::test]
async fn a_member_reuses_a_checkpoint_without_losing_history_after_restart() {
    use elo_core::{
        authority::Authority,
        store::{ClientStore, LocalTime},
    };
    let (owner, reader, authority, messages) = setup();
    let encrypted = authority
        .seal_snapshot_signed(&reader.age.to_public(), &owner.key)
        .unwrap();
    let received = Authority::open_snapshot(
        &encrypted,
        &reader.age,
        authority.space(),
        &owner.root.verifying_key(),
        authority.stream(),
    )
    .unwrap();
    assert_eq!(received.call_proof_signed(&reader.key).unwrap().v, 2);
    received.verify_historical(&messages[0]).unwrap();
    let temp = tempfile::tempdir().unwrap();
    let store = ClientStore::open(temp.path()).await.unwrap();
    received
        .merge_into_store(
            None,
            &store,
            &reader.age,
            LocalTime::from_millis(1).unwrap(),
        )
        .await
        .unwrap();
    let persisted = store
        .authority_snapshot(authority.space(), authority.stream())
        .await
        .unwrap()
        .unwrap();
    let reopened = Authority::open_snapshot(
        &persisted,
        &reader.age,
        authority.space(),
        &owner.root.verifying_key(),
        authority.stream(),
    )
    .unwrap();
    assert_eq!(reopened.call_proof_signed(&reader.key).unwrap().v, 2);
    reopened.verify_historical(&messages[0]).unwrap();
}
