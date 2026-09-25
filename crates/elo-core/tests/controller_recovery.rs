mod common {
    pub mod authority_fixture;
}
use base64::{Engine, engine::general_purpose::STANDARD};
use common::authority_fixture::{Person, setup};
use ed25519_dalek::SigningKey;
use elo_core::{
    authority::{Admission, Authority, ConfigAdmission, ControllerRecovery},
    crypto,
    identity::DeviceCredential,
    record::{SignedRecord, random_hex},
    store::{ClientStore, LocalTime},
};

fn fresh(owner: &Person, seed: u8) -> Person {
    let root = owner.root.clone();
    let key = SigningKey::from_bytes(&[seed; 32]);
    let age = age::x25519::Identity::generate();
    let c = DeviceCredential::issue(&root, &key.verifying_key(), &age.to_public()).unwrap();
    Person { root, key, age, c }
}
fn recover(a: &Authority, owner: &Person, new: &Person) -> (Authority, SignedRecord, SignedRecord) {
    let mut a = a.clone();
    a.add_credential(new.c.clone());
    let cert = a.sign_recovery(&new.c, &owner.root).unwrap();
    let config = a.prepare_recovery(&cert, &new.key).unwrap();
    assert_eq!(
        a.apply_config(config.clone()).unwrap(),
        ConfigAdmission::Applied
    );
    (a, cert, config)
}
fn advance(a: &Authority, signer: &Person) -> SignedRecord {
    let mut c = a.head().unwrap().clone();
    c.sequence += 1;
    c.previous_config_id = a.head_id();
    c.nonce = random_hex::<16>().unwrap();
    c.recovery = None;
    c.action.operation = "replace".into();
    c.action.request_record_id = None;
    c.sign(&signer.key).unwrap()
}
fn set_owner_devices(a: &mut Authority, controller: &Person, devices: &[&Person]) {
    for device in devices {
        a.add_credential(device.c.clone());
    }
    let mut c = a.head().unwrap().clone();
    let member = c
        .members
        .iter_mut()
        .find(|m| m.identity_id == controller.c.identity())
        .unwrap();
    member.credential_ids = devices.iter().map(|d| d.c.id()).collect();
    member.credential_ids.sort();
    c.owner_credential_ids = member.credential_ids.clone();
    c.sequence += 1;
    c.previous_config_id = a.head_id();
    c.nonce = random_hex::<16>().unwrap();
    c.recovery = None;
    c.action.operation = "device.updated".into();
    c.action.request_record_id = None;
    assert_eq!(
        a.apply_config(c.sign(&controller.key).unwrap()).unwrap(),
        ConfigAdmission::Applied
    );
}
#[test]
fn recovery_accepts_an_enrolled_device_but_not_removed_or_reissued_keys() {
    let (owner, _, mut a, _) = setup();
    let new = fresh(&owner, 99);
    set_owner_devices(&mut a, &owner, &[&owner, &new]);
    let (recovered, _, _) = recover(&a, &owner, &new);
    assert_eq!(recovered.controller().id(), new.c.id());
    // Admission is not sufficient: the explicit root authorization is required.
    assert!(a.apply_config(advance(&a, &new)).is_err());
    for reuse_signing in [false, true] {
        let unrelated = fresh(&owner, 100);
        let key = if reuse_signing {
            &new.key
        } else {
            &unrelated.key
        };
        let age = if reuse_signing {
            &unrelated.age
        } else {
            &new.age
        };
        let credential =
            DeviceCredential::issue(&owner.root, &key.verifying_key(), &age.to_public()).unwrap();
        let mut alias = a.clone();
        alias.add_credential(credential.clone());
        let cert = alias.sign_recovery(&credential, &owner.root).unwrap();
        assert!(alias.prepare_recovery(&cert, key).is_err());
    }
    set_owner_devices(&mut a, &owner, &[&owner]);
    let cert = a.sign_recovery(&new.c, &owner.root).unwrap();
    assert!(a.prepare_recovery(&cert, &new.key).is_err());
}
#[test]
fn readmitting_a_former_controller_does_not_allow_recovery_with_its_old_keys() {
    let (owner, _, old, _) = setup();
    let new = fresh(&owner, 99);
    let (mut a, _, _) = recover(&old, &owner, &new);
    set_owner_devices(&mut a, &new, &[&owner, &new]);
    let cert = a.sign_recovery(&owner.c, &owner.root).unwrap();
    assert!(a.prepare_recovery(&cert, &owner.key).is_err());
}
#[test]
fn lost_controller_replaced_without_changing_space_history_or_other_members() {
    let (owner, reader, old, messages) = setup();
    let new = fresh(&owner, 99);
    let (mut a, cert, config) = recover(&old, &owner, &new);
    assert_eq!(a.space(), old.space());
    assert_eq!(a.genesis().bytes(), old.genesis().bytes());
    assert_eq!(a.controller().id(), new.c.id());
    assert_eq!(a.recovery_id(), Some(cert.id()));
    assert_eq!(
        a.head()
            .unwrap()
            .members
            .iter()
            .find(|m| m.identity_id == reader.c.identity()),
        old.head()
            .unwrap()
            .members
            .iter()
            .find(|m| m.identity_id == reader.c.identity())
    );
    for r in &messages {
        a.verify_historical(r).unwrap();
    }
    let mut chat = messages[0].chat().unwrap();
    chat.issuer_credential = new.c.id();
    let r = a.prepare_chat(chat.clone(), &new.key).unwrap();
    let recipients = r
        .chat()
        .unwrap()
        .recipient_credentials
        .iter()
        .map(|id| a.credential(*id).unwrap().clone())
        .collect::<Vec<_>>();
    let cipher = crypto::seal_chat(&r, &recipients).unwrap();
    assert!(crypto::open_object(&cipher, &owner.age).is_err());
    assert_eq!(
        crypto::open_object(&cipher, &new.age).unwrap().bytes(),
        r.bytes()
    );
    assert_eq!(
        crypto::open_object(&cipher, &reader.age).unwrap().bytes(),
        r.bytes()
    );
    chat.issuer_credential = owner.c.id();
    assert!(a.prepare_chat(chat, &owner.key).is_err());
    assert_eq!(
        a.apply_config(config).unwrap(),
        ConfigAdmission::AlreadyPresent
    );
    assert_eq!(
        a.apply_config(advance(&old, &owner)).unwrap(),
        ConfigAdmission::Historical
    );
    assert_eq!(a.controller().id(), new.c.id());
    assert!(!a.is_forked());
    assert_eq!(
        a.admission(&messages[0], owner.c.id(), false).unwrap(),
        Admission::QuarantinedStale
    );
    assert_eq!(
        a.admission(&messages[0], owner.c.id(), true).unwrap(),
        Admission::Accepted
    );
    let next = advance(&a, &new);
    assert_eq!(a.apply_config(next).unwrap(), ConfigAdmission::Applied);
}
#[test]
fn recovery_requires_root_fresh_keys_exact_membership_and_bound_space() {
    let (owner, reader, old, _) = setup();
    let new = fresh(&owner, 99);
    let (valid, cert, config) = recover(&old, &owner, &new);
    let mut a = old.clone();
    a.add_credential(new.c.clone());
    let mut b: ControllerRecovery = cert.decode().unwrap();
    b.space_id = elo_core::ids::SpaceId::from_bytes([9; 32]);
    let wrong_space = SignedRecord::sign(&serde_json::to_vec(&b).unwrap(), &owner.root).unwrap();
    assert!(a.prepare_recovery(&wrong_space, &new.key).is_err());
    let wrong_key = SignedRecord::sign(
        &serde_json::to_vec(&cert.decode::<ControllerRecovery>().unwrap()).unwrap(),
        &owner.key,
    )
    .unwrap();
    assert!(a.prepare_recovery(&wrong_key, &new.key).is_err());
    assert!(a.sign_recovery(&new.c, &reader.root).is_err());
    assert!(a.sign_recovery(&reader.c, &owner.root).is_err());
    let mut c = valid.head().unwrap().clone();
    c.members.retain(|m| m.identity_id != reader.c.identity());
    assert!(a.apply_config(c.sign(&new.key).unwrap()).is_err());
    let mut c = config
        .decode::<elo_core::authority::StreamConfig>()
        .unwrap();
    c.recovery = None;
    c.action.operation = "replace".into();
    assert!(a.apply_config(c.sign(&new.key).unwrap()).is_err());
    // A new credential wrapping either old secret does not count as recovery.
    for reuse_signing in [false, true] {
        let key = if reuse_signing {
            owner.key.clone()
        } else {
            new.key.clone()
        };
        let age = if reuse_signing {
            new.age.clone()
        } else {
            owner.age.clone()
        };
        let c =
            DeviceCredential::issue(&owner.root, &key.verifying_key(), &age.to_public()).unwrap();
        a.add_credential(c.clone());
        let cert = a.sign_recovery(&c, &owner.root).unwrap();
        assert!(a.prepare_recovery(&cert, &key).is_err());
    }
    assert_eq!(a.head_id(), old.head_id());
    assert_eq!(a.controller().id(), owner.c.id());
}
#[test]
fn missing_checkpoint_waits_and_recovery_forks_freeze_without_timestamp_tiebreak() {
    let (owner, _, old, _) = setup();
    let new = fresh(&owner, 99);
    let other = fresh(&owner, 100);
    let (mut a, _, first) = recover(&old, &owner, &new);
    let (_, _, sibling) = recover(&old, &owner, &other);
    a.add_credential(other.c.clone());
    assert_eq!(a.apply_config(sibling).unwrap(), ConfigAdmission::Forked);
    assert!(a.is_forked());
    assert!(a.sign_recovery(&fresh(&owner, 101).c, &owner.root).is_err());
    let mut empty = Authority::new(
        old.genesis().bytes(),
        old.space(),
        &owner.root.verifying_key(),
        owner.c.clone(),
        old.stream(),
    )
    .unwrap();
    empty.add_credential(new.c.clone());
    // The config also needs all member credential proofs before its parent check.
    for m in &old.head().unwrap().members {
        for id in &m.credential_ids {
            empty.add_credential(old.credential(*id).unwrap().clone());
        }
    }
    assert_eq!(
        empty.apply_config(first).unwrap(),
        ConfigAdmission::WaitingForProof
    );
    assert_eq!(empty.head_id(), None);
}
#[test]
fn subsequent_recovery_chains_and_old_certificate_cannot_roll_back() {
    let (owner, _, old, _) = setup();
    let new = fresh(&owner, 99);
    let next = fresh(&owner, 100);
    let (a, cert1, first) = recover(&old, &owner, &new);
    let (mut b, cert2, _) = recover(&a, &owner, &next);
    let body: ControllerRecovery = cert2.decode().unwrap();
    assert_eq!(body.sequence, 2);
    assert_eq!(body.previous_recovery_id, Some(cert1.id()));
    assert_eq!(
        b.apply_config(first).unwrap(),
        ConfigAdmission::AlreadyPresent
    );
    assert_eq!(
        b.apply_config(advance(&a, &new)).unwrap(),
        ConfigAdmission::Historical
    );
    assert_eq!(b.controller().id(), next.c.id());
    assert!(b.prepare_recovery(&cert1, &new.key).is_err());
    let mut forged = body.clone();
    forged.previous_recovery_id = None;
    let r = SignedRecord::sign(&serde_json::to_vec(&forged).unwrap(), &owner.root).unwrap();
    assert!(b.prepare_recovery(&r, &next.key).is_err());
}
#[tokio::test]
async fn recovery_restart_rollback_merge_and_snapshot_cas_preserve_evidence() {
    let (owner, _, old, _) = setup();
    let new = fresh(&owner, 99);
    let (incoming, _, recovered) = recover(&old, &owner, &new);
    let dir = tempfile::TempDir::new().unwrap();
    let store = ClientStore::open(dir.path()).await.unwrap();
    let time = LocalTime::from_millis(1).unwrap();
    let mut a = old
        .merge_into_store(None, &store, &new.age, time)
        .await
        .unwrap();
    a.add_credential(new.c.clone());
    a.commit_update(&store, recovered, &new.age, time)
        .await
        .unwrap();
    let a = old
        .merge_into_store(Some(&a), &store, &new.age, time)
        .await
        .unwrap();
    assert_eq!(a.head_id(), incoming.head_id());
    let mut stale = a.clone();
    let mut current = a.clone();
    // Two old-generation branches preserve the head, but still change evidence.
    current
        .commit_update(&store, advance(&old, &owner), &new.age, time)
        .await
        .unwrap();
    assert!(
        stale
            .commit_update(&store, advance(&old, &owner), &new.age, time)
            .await
            .is_err()
    );
    let snapshot = store
        .authority_snapshot(a.space(), a.stream())
        .await
        .unwrap()
        .unwrap();
    store.close().await.unwrap();
    let restored = Authority::open_snapshot(
        &snapshot,
        &new.age,
        a.space(),
        &owner.root.verifying_key(),
        a.stream(),
    )
    .unwrap();
    assert_eq!(restored.head_id(), a.head_id());
    assert_eq!(restored.controller().id(), new.c.id());
    assert_eq!(restored.recovery_id(), a.recovery_id());
    assert!(
        Authority::open_snapshot(
            &snapshot,
            &owner.age,
            a.space(),
            &owner.root.verifying_key(),
            a.stream()
        )
        .is_err()
    );
}
#[test]
fn different_checkpoints_in_one_recovery_generation_are_a_fork() {
    let (owner, _, mut old, _) = setup();
    let new = fresh(&owner, 99);
    let (mut a, cert, _) = recover(&old, &owner, &new);
    old.apply_config(advance(&old, &owner)).unwrap();
    old.add_credential(new.c.clone());
    let sibling = old.prepare_recovery(&cert, &new.key).unwrap();
    let parent = old.config_record(old.head_id().unwrap()).unwrap().clone();
    a.apply_config(parent).unwrap();
    assert_eq!(a.apply_config(sibling).unwrap(), ConfigAdmission::Forked);
}
#[test]
fn recovery_certificate_bytes_are_covered_by_the_new_device_signature() {
    let (owner, _, old, _) = setup();
    let new = fresh(&owner, 99);
    let (_, _, r) = recover(&old, &owner, &new);
    let c: elo_core::authority::StreamConfig = r.decode().unwrap();
    let cert = STANDARD.decode(c.recovery.unwrap()).unwrap();
    assert_eq!(
        SignedRecord::parse(&cert).unwrap().body()["kind"],
        "space.controller.recovered"
    );
    let mut bytes = r.bytes().to_vec();
    let at = bytes
        .windows(20)
        .position(|x| x == &r.bytes()[100..120])
        .unwrap();
    bytes[at] ^= 1;
    assert!(
        SignedRecord::parse(&bytes)
            .and_then(|r| r.verify_signature(&new.key.verifying_key()))
            .is_err()
    );
}

#[test]
fn one_space_certificate_is_reused_across_streams_and_invitation_proofs_are_bound() {
    let (owner, reader, old, _) = setup();
    let new = fresh(&owner, 99);
    let (recovered, certificate, _) = recover(&old, &owner, &new);
    assert!(recovered.controller_ready_with(&[]));
    assert!(recovered.controller_ready_with(std::slice::from_ref(&old)));
    assert!(!old.controller_ready_with(std::slice::from_ref(&recovered)));
    let stream = elo_core::ids::StreamId::from_bytes([3; 16]);
    let mut second = Authority::new(
        old.genesis().bytes(),
        old.space(),
        &owner.root.verifying_key(),
        owner.c.clone(),
        stream,
    )
    .unwrap();
    second.add_credential(reader.c.clone());
    let mut first = old
        .config(old.head().unwrap().previous_config_id.unwrap())
        .unwrap()
        .clone();
    first.stream_id = stream;
    second
        .apply_config(first.sign(&owner.key).unwrap())
        .unwrap();
    let mut last = old.head().unwrap().clone();
    last.stream_id = stream;
    last.previous_config_id = second.head_id();
    second.apply_config(last.sign(&owner.key).unwrap()).unwrap();
    second.add_credential(new.c.clone());
    let second_before_recovery = second.clone();
    let config = second.prepare_recovery(&certificate, &new.key).unwrap();
    second.apply_config(config).unwrap();
    assert_eq!(second.recovery_id(), recovered.recovery_id());
    assert!(second.controller_ready_with(std::slice::from_ref(&recovered)));
    assert!(recovered.controller_ready_with(std::slice::from_ref(&second)));
    let other = fresh(&owner, 100);
    let (conflicting, _, _) = recover(&second_before_recovery, &owner, &other);
    assert!(!recovered.controller_ready_with(std::slice::from_ref(&conflicting)));
    assert!(!conflicting.controller_ready_with(std::slice::from_ref(&recovered)));
    let chain = recovered.controller_recovery_chain().unwrap();
    old.verify_controller_export(&chain, &new.c).unwrap();
    assert!(old.verify_controller_export(&[], &new.c).is_err());
    assert!(old.verify_controller_export(&chain, &owner.c).is_err());
    assert!(old.verify_controller_export(&chain, &reader.c).is_err());
    assert!(
        old.verify_controller_export(&[chain[0].clone(), chain[0].clone()], &new.c)
            .is_err()
    );
    let (_, _, foreign, _) = setup();
    assert!(foreign.verify_controller_export(&chain, &new.c).is_err());
}

#[tokio::test]
async fn sqlite_failure_does_not_partially_recover_and_old_outbox_is_held_on_success() {
    use elo_core::store::{DeliveryTarget, PreparedLocalRecord, RecordMetadata};
    let (owner, _, old, messages) = setup();
    let new = fresh(&owner, 99);
    let (_, _, recovery) = recover(&old, &owner, &new);
    let dir = tempfile::TempDir::new().unwrap();
    let store = ClientStore::open(dir.path()).await.unwrap();
    let time = LocalTime::from_millis(1).unwrap();
    let mut a = old
        .merge_into_store(None, &store, &new.age, time)
        .await
        .unwrap();
    a.add_credential(new.c.clone());
    let mut chat = messages[0].chat().unwrap();
    chat.nonce = random_hex::<16>().unwrap();
    let record = a.prepare_chat(chat, &owner.key).unwrap();
    let recipients = record
        .chat()
        .unwrap()
        .recipient_credentials
        .iter()
        .map(|id| a.credential(*id).unwrap().clone())
        .collect::<Vec<_>>();
    store
        .commit_local_record_with_outbox(
            PreparedLocalRecord::new(
                record.id(),
                crypto::seal_chat(&record, &recipients).unwrap(),
                RecordMetadata::new(
                    "chat.message",
                    Some(a.space()),
                    Some(a.stream()),
                    a.head_id(),
                )
                .unwrap(),
                vec![DeliveryTarget {
                    peer_id: elo_core::ids::PeerId::from_bytes([5; 32]),
                    mailbox_id: elo_core::ids::MailboxId::from_bytes([6; 32]),
                }],
                time,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let before = store
        .authority_snapshot(a.space(), a.stream())
        .await
        .unwrap();
    let db = rusqlite::Connection::open(dir.path().join("client.sqlite")).unwrap();
    db.execute_batch("CREATE TRIGGER reject_snapshot BEFORE UPDATE ON authority_snapshots BEGIN SELECT RAISE(ABORT,'synthetic disk write failure'); END;").unwrap();
    assert!(
        a.commit_update(&store, recovery.clone(), &new.age, time)
            .await
            .is_err()
    );
    assert_eq!(a.controller().id(), owner.c.id());
    assert_eq!(
        store
            .authority_snapshot(a.space(), a.stream())
            .await
            .unwrap(),
        before
    );
    assert_eq!(store.stats().await.unwrap().held, 0);
    assert_eq!(store.stats().await.unwrap().pending, 1);
    db.execute_batch("DROP TRIGGER reject_snapshot;").unwrap();
    a.commit_update(&store, recovery, &new.age, time)
        .await
        .unwrap();
    assert_eq!(a.controller().id(), new.c.id());
    assert_eq!(store.stats().await.unwrap().held, 1);
    assert_eq!(store.stats().await.unwrap().pending, 0);
    store.close().await.unwrap();
}

#[test]
fn explicit_history_grant_after_recovery_preserves_original_signatures() {
    use elo_core::history;
    let (owner, reader, old, messages) = setup();
    let new = fresh(&owner, 99);
    let (a, _, _) = recover(&old, &owner, &new);
    let mut chat = messages[0].chat().unwrap();
    chat.issuer_credential = new.c.id();
    chat.logical_time = 999;
    let recent = a.prepare_chat(chat, &new.key).unwrap();
    let selection = vec![messages[0].clone(), recent];
    let request = history::create_request(&a, reader.c.id(), 20, None, &reader.key).unwrap();
    let grant = history::approve(&a, &request, new.c.id(), &selection, &new.key).unwrap();
    let ciphertext = history::seal(&a, &grant).unwrap();
    let verified =
        history::VerifiedBundle::open(&ciphertext, &reader.age, reader.c.id(), &a, &request)
            .unwrap();
    assert_eq!(verified.originals()[0].bytes(), messages[0].bytes());
    assert!(
        history::VerifiedBundle::open(&ciphertext, &owner.age, owner.c.id(), &a, &request).is_err()
    );
}
