use ed25519_dalek::SigningKey;
use elo_core::{
    authority::{
        Admission, Authority, Capability, ConfigAction, ConfigAdmission, Member, Owner,
        SpaceGenesis, StreamConfig,
    },
    crypto,
    identity::{DeviceCredential, VerifiedCredential},
    ids::{RecordId, StreamId},
    record::{SignedRecord, encode_hex, random_hex},
    store::{ClientStore, DeliveryTarget, LocalTime, PreparedLocalRecord, RecordMetadata},
    sync::ChatAuthority,
};
struct Person {
    root: SigningKey,
    key: SigningKey,
    age: age::x25519::Identity,
    c: VerifiedCredential,
}
fn person(seed: u8) -> Person {
    let root = SigningKey::from_bytes(&[seed; 32]);
    let key = SigningKey::from_bytes(&[seed + 1; 32]);
    let age = age::x25519::Identity::generate();
    let c = DeviceCredential::issue(&root, &key.verifying_key(), &age.to_public()).unwrap();
    Person { root, key, age, c }
}
fn member(p: &Person, capabilities: Vec<Capability>) -> Member {
    Member {
        identity_id: p.c.identity(),
        identity_type: "HUMAN".into(),
        root_public_key: encode_hex(p.root.verifying_key().as_bytes()),
        capabilities,
        credential_ids: vec![p.c.id()],
        external: false,
    }
}
fn setup() -> (Person, Authority, StreamConfig) {
    let owner = person(10);
    let g = SpaceGenesis {
        v: 1,
        kind: "space.genesis".into(),
        nonce: random_hex::<16>().unwrap(),
        issuer_identity: owner.c.identity(),
        owners: vec![Owner {
            identity_id: owner.c.identity(),
            root_public_key: encode_hex(owner.root.verifying_key().as_bytes()),
        }],
        controller_credential_id: owner.c.id(),
    };
    let r = SignedRecord::sign(&serde_json::to_vec(&g).unwrap(), &owner.root).unwrap();
    let a = Authority::new(
        r.bytes(),
        r.id().to_string().parse().unwrap(),
        &owner.root.verifying_key(),
        owner.c.clone(),
        StreamId::from_bytes([2; 16]),
    )
    .unwrap();
    let c = StreamConfig {
        chat_kind: None,
        recovery: None,
        v: 1,
        kind: "stream.config".into(),
        nonce: random_hex::<16>().unwrap(),
        space_id: a.space(),
        stream_id: a.stream(),
        sequence: 1,
        previous_config_id: None,
        controller_credential_id: owner.c.id(),
        members: vec![member(
            &owner,
            vec![
                Capability::Read,
                Capability::Post,
                Capability::ShareHistory,
                Capability::Manage,
            ],
        )],
        owner_credential_ids: vec![owner.c.id()],
        action: ConfigAction {
            operation: "create".into(),
            actor_identity: owner.c.identity(),
            request_record_id: None,
        },
    };
    (owner, a, c)
}
fn advance(c: &StreamConfig, head: RecordId) -> StreamConfig {
    let mut c = c.clone();
    c.sequence += 1;
    c.previous_config_id = Some(head);
    c.nonce = random_hex::<16>().unwrap();
    c.action.operation = "replace".into();
    c
}
#[test]
fn chat_kind_is_signed_preserved_and_can_only_be_set_once_on_legacy_configs() {
    use elo_core::authority::ChatKind;
    let (owner, mut authority, legacy) = setup();
    let signed = legacy.sign(&owner.key).unwrap();
    assert!(signed.body().get("chat_kind").is_none());
    authority.apply_config(signed).unwrap();
    let mut typed = advance(&legacy, authority.head_id().unwrap());
    typed.chat_kind = Some(ChatKind::Direct);
    authority
        .apply_config(typed.sign(&owner.key).unwrap())
        .unwrap();
    let expected_head = authority.head_id();
    for kind in [None, Some(ChatKind::Chat)] {
        let mut changed = advance(&typed, expected_head.unwrap());
        changed.chat_kind = kind;
        assert!(
            authority
                .apply_config(changed.sign(&owner.key).unwrap())
                .is_err()
        );
        assert_eq!(authority.head_id(), expected_head);
    }
    let next = advance(&typed, expected_head.unwrap());
    let mut body = serde_json::to_value(&next).unwrap();
    body["chat_kind"] = serde_json::json!("unknown");
    let invalid = SignedRecord::sign(&serde_json::to_vec(&body).unwrap(), &owner.key).unwrap();
    assert!(authority.apply_config(invalid).is_err());
    assert_eq!(authority.head_id(), expected_head);
    authority
        .apply_config(next.sign(&owner.key).unwrap())
        .unwrap();
    let sealed = authority.seal_snapshot(&owner.age.to_public()).unwrap();
    let restored = Authority::open_snapshot(
        &sealed,
        &owner.age,
        authority.space(),
        &owner.root.verifying_key(),
        authority.stream(),
    )
    .unwrap();
    assert_eq!(restored.head().unwrap().chat_kind, Some(ChatKind::Direct));
    assert_eq!(restored.head().unwrap().members, legacy.members);
}
fn chat(a: &Authority, p: &Person) -> SignedRecord {
    let mut c = SignedRecord::parse(include_bytes!(
        "../../../protocol/fixtures/chat-message-v1.record.bin"
    ))
    .unwrap()
    .chat()
    .unwrap();
    c.issuer_credential = p.c.id();
    a.prepare_chat(c, &p.key).unwrap()
}

#[test]
fn early_acceptance_capability_requires_a_two_human_direct_configuration() {
    use elo_core::{authority::ChatKind, record::MessageAccess, retention_access::public_key};
    for kind in [ChatKind::Direct, ChatKind::Chat] {
        let (owner, mut authority, mut config) = setup();
        let peer = person(60);
        authority.add_credential(peer.c.clone());
        config
            .members
            .push(member(&peer, vec![Capability::Read, Capability::Post]));
        config.members.sort_by_key(|member| member.identity_id);
        config.chat_kind = Some(kind);
        authority
            .apply_config(config.sign(&owner.key).unwrap())
            .unwrap();
        let mut message = chat(&authority, &owner).chat().unwrap();
        message.access = Some(MessageAccess {
            request_key: public_key(&random_hex::<32>().unwrap()).unwrap(),
            accept_secret: Some(random_hex::<32>().unwrap()),
        });
        let message = message.sign(&owner.key).unwrap();
        assert_eq!(
            authority.verify_historical(&message).is_ok(),
            kind == ChatKind::Direct
        );
    }
}
#[test]
fn unpinned_genesis_and_credential_without_membership_are_denied() {
    let (owner, mut a, c) = setup();
    let outsider = person(20);
    assert!(
        Authority::new(
            a.genesis().bytes(),
            elo_core::ids::SpaceId::from_bytes([9; 32]),
            &owner.root.verifying_key(),
            owner.c.clone(),
            a.stream()
        )
        .is_err()
    );
    assert!(
        Authority::new(
            a.genesis().bytes(),
            a.space(),
            &outsider.root.verifying_key(),
            owner.c.clone(),
            a.stream()
        )
        .is_err()
    );
    a.add_credential(outsider.c.clone());
    a.apply_config(c.sign(&owner.key).unwrap()).unwrap();
    let mut message = chat(&a, &owner).chat().unwrap();
    message.issuer_identity = outsider.c.identity();
    message.issuer_credential = outsider.c.id();
    assert!(
        a.verify(&message.sign(&outsider.key).unwrap(), owner.c.id())
            .is_err()
    );
}
#[test]
fn missing_parent_waits_and_signed_siblings_freeze_the_stream() {
    let (owner, mut a, c) = setup();
    let first = c.sign(&owner.key).unwrap();
    let child = advance(&c, first.id()).sign(&owner.key).unwrap();
    assert_eq!(
        a.apply_config(child.clone()).unwrap(),
        ConfigAdmission::WaitingForProof
    );
    a.apply_config(first.clone()).unwrap();
    a.apply_config(child).unwrap();
    let sibling = advance(&c, first.id()).sign(&owner.key).unwrap();
    assert_eq!(a.apply_config(sibling).unwrap(), ConfigAdmission::Forked);
    let message = SignedRecord::parse(include_bytes!(
        "../../../protocol/fixtures/chat-message-v1.record.bin"
    ))
    .unwrap()
    .chat()
    .unwrap();
    assert!(a.prepare_chat(message, &owner.key).is_err());
}
#[test]
fn joining_cannot_read_old_ciphertext_and_revoked_device_cannot_read_new() {
    let (owner, mut a, c) = setup();
    let bob = person(20);
    a.apply_config(c.sign(&owner.key).unwrap()).unwrap();
    let old = chat(&a, &owner);
    let old_c = crypto::seal_chat(&old, std::slice::from_ref(&owner.c)).unwrap();
    a.add_credential(bob.c.clone());
    let mut join = advance(&c, a.head_id().unwrap());
    join.members
        .push(member(&bob, vec![Capability::Read, Capability::Post]));
    join.members.sort_by_key(|m| m.identity_id);
    a.apply_config(join.sign(&owner.key).unwrap()).unwrap();
    assert!(crypto::open_record(&old_c, &bob.age).is_err());
    let joined = chat(&a, &owner);
    let recipients = joined
        .chat()
        .unwrap()
        .recipient_credentials
        .iter()
        .map(|id| a.credential(*id).unwrap().clone())
        .collect::<Vec<_>>();
    let encrypted = crypto::seal_chat(&joined, &recipients).unwrap();
    assert!(crypto::open_record(&encrypted, &bob.age).is_ok());
    let partition = a.clone();
    let mut revoke = advance(&join, a.head_id().unwrap());
    revoke.members.retain(|m| m.identity_id != bob.c.identity());
    a.apply_config(revoke.sign(&owner.key).unwrap()).unwrap();
    let new = chat(&a, &owner);
    let bytes = crypto::seal_chat(&new, std::slice::from_ref(&owner.c)).unwrap();
    assert!(crypto::open_record(&bytes, &bob.age).is_err());
    assert_eq!(
        a.admission(&joined, owner.c.id(), false).unwrap(),
        Admission::QuarantinedStale
    );
    assert_eq!(
        a.admission(&joined, owner.c.id(), true).unwrap(),
        Admission::Accepted
    );
    assert!(
        partition
            .verify(&chat(&partition, &bob), owner.c.id())
            .is_ok()
    );
}
#[test]
fn post_only_has_own_copy_but_no_other_messages() {
    let (owner, mut a, mut c) = setup();
    let publisher = person(20);
    a.add_credential(publisher.c.clone());
    c.members.push(member(&publisher, vec![Capability::Post]));
    c.members.sort_by_key(|m| m.identity_id);
    a.apply_config(c.sign(&owner.key).unwrap()).unwrap();
    let own = chat(&a, &publisher);
    assert!(
        !own.chat()
            .unwrap()
            .audience
            .contains(&publisher.c.identity())
    );
    let recipients = own
        .chat()
        .unwrap()
        .recipient_credentials
        .iter()
        .map(|id| a.credential(*id).unwrap().clone())
        .collect::<Vec<_>>();
    assert!(
        crypto::open_record(
            &crypto::seal_chat(&own, &recipients).unwrap(),
            &publisher.age
        )
        .is_ok()
    );
    let other = chat(&a, &owner);
    assert!(
        crypto::open_record(
            &crypto::seal_chat(&other, std::slice::from_ref(&owner.c)).unwrap(),
            &publisher.age
        )
        .is_err()
    );
}
#[test]
fn owner_omission_relabelled_root_unknown_caps_and_bad_audience_fail() {
    let (owner, mut a, c) = setup();
    let mut invalid = c.clone();
    invalid.owner_credential_ids.clear();
    assert!(a.apply_config(invalid.sign(&owner.key).unwrap()).is_err());
    let mut invalid = c.clone();
    invalid.members[0].root_public_key = "00".repeat(32);
    assert!(a.apply_config(invalid.sign(&owner.key).unwrap()).is_err());
    let mut invalid = c.clone();
    invalid.members[0].capabilities = vec![Capability::Post];
    assert!(a.apply_config(invalid.sign(&owner.key).unwrap()).is_err());
    a.apply_config(c.sign(&owner.key).unwrap()).unwrap();
    let original = chat(&a, &owner);
    let mut bad = original.chat().unwrap();
    bad.audience = vec![elo_core::ids::IdentityId::from_bytes([0; 32])];
    assert!(
        a.verify(&bad.sign(&owner.key).unwrap(), owner.c.id())
            .is_err()
    );
}
#[tokio::test]
async fn config_cas_hold_and_encrypted_snapshot_are_one_durable_update() {
    let (owner, mut a, c) = setup();
    let dir = tempfile::TempDir::new().unwrap();
    let store = ClientStore::open(dir.path()).await.unwrap();
    a.commit_update(
        &store,
        c.sign(&owner.key).unwrap(),
        &owner.age,
        LocalTime::from_millis(1).unwrap(),
    )
    .await
    .unwrap();
    let msg = chat(&a, &owner);
    store
        .commit_local_record_with_outbox(
            PreparedLocalRecord::new(
                msg.id(),
                crypto::seal_chat(&msg, std::slice::from_ref(&owner.c)).unwrap(),
                RecordMetadata::new(
                    "chat.message",
                    Some(a.space()),
                    Some(a.stream()),
                    a.head_id(),
                )
                .unwrap(),
                vec![DeliveryTarget {
                    peer_id: elo_core::ids::PeerId::from_bytes([1; 32]),
                    mailbox_id: elo_core::ids::MailboxId::from_bytes([2; 32]),
                }],
                LocalTime::from_millis(1).unwrap(),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let mut stale = a.clone();
    let update = advance(&c, a.head_id().unwrap());
    a.commit_update(
        &store,
        update.sign(&owner.key).unwrap(),
        &owner.age,
        LocalTime::from_millis(2).unwrap(),
    )
    .await
    .unwrap();
    assert!(
        stale
            .commit_update(
                &store,
                advance(&c, stale.head_id().unwrap())
                    .sign(&owner.key)
                    .unwrap(),
                &owner.age,
                LocalTime::from_millis(3).unwrap()
            )
            .await
            .is_err()
    );
    assert_eq!(store.stats().await.unwrap().held, 1);
    let expected = a.head_id();
    store.close().await.unwrap();
    let store = ClientStore::open(dir.path()).await.unwrap();
    let snapshot = store
        .authority_snapshot(a.space(), a.stream())
        .await
        .unwrap()
        .unwrap();
    let restored = Authority::open_snapshot(
        &snapshot,
        &owner.age,
        a.space(),
        &owner.root.verifying_key(),
        a.stream(),
    )
    .unwrap();
    assert_eq!(restored.head_id(), expected);
    assert!(
        Authority::open_snapshot(
            &snapshot,
            &age::x25519::Identity::generate(),
            a.space(),
            &owner.root.verifying_key(),
            a.stream()
        )
        .is_err()
    );
    store.close().await.unwrap();
}

#[tokio::test]
async fn invitation_needs_candidate_signature_confirmed_fingerprint_and_current_head() {
    let (owner, mut a, c) = setup();
    let bob = person(20);
    let dir = tempfile::TempDir::new().unwrap();
    let store = ClientStore::open(dir.path()).await.unwrap();
    a.commit_update(
        &store,
        c.sign(&owner.key).unwrap(),
        &owner.age,
        LocalTime::from_millis(1).unwrap(),
    )
    .await
    .unwrap();
    let invite = elo_core::invite::create(&a, &owner.key).unwrap();
    let request = elo_core::invite::request(&invite, a.controller(), &bob.c, &bob.key).unwrap();
    // The transport is a file of exact signed bytes, not a link granting access.
    let path = dir.path().join("candidate-request.elo");
    std::fs::write(&path, request.bytes()).unwrap();
    let request = SignedRecord::parse(&std::fs::read(path).unwrap()).unwrap();
    let approval = |confirmed| elo_core::invite::CandidateApproval {
        invitation: invite.clone(),
        request: request.clone(),
        credential: bob.c.clone(),
        confirmed_identity: confirmed,
        capabilities: vec![Capability::Read, Capability::Post],
    };
    assert!(
        elo_core::invite::approve(
            &mut a,
            &store,
            approval(owner.c.identity()),
            &owner.key,
            &owner.age,
            LocalTime::from_millis(2).unwrap()
        )
        .await
        .is_err()
    );
    assert_eq!(
        elo_core::invite::approve(
            &mut a,
            &store,
            approval(bob.c.identity()),
            &owner.key,
            &owner.age,
            LocalTime::from_millis(2).unwrap()
        )
        .await
        .unwrap(),
        ConfigAdmission::Applied
    );
    assert!(a.has(a.head_id().unwrap(), bob.c.identity(), Capability::Read));
    assert!(
        elo_core::invite::approve(
            &mut a,
            &store,
            approval(bob.c.identity()),
            &owner.key,
            &owner.age,
            LocalTime::from_millis(3).unwrap()
        )
        .await
        .is_err()
    );
    let raw = rusqlite::Connection::open(dir.path().join("client.sqlite")).unwrap();
    assert_eq!(
        raw.query_row::<i64, _, _>("SELECT count(*) FROM used_invites", [], |r| r.get(0))
            .unwrap(),
        1
    );
    store.close().await.unwrap();
}

#[test]
fn a_chat_accepts_1000_people_and_rejects_the_1001st_without_changing_its_head() {
    let (owner, mut authority, mut config) = setup();
    let mut last = None;
    for index in 1u64..=1000 {
        let mut seed = [0u8; 32];
        seed[..8].copy_from_slice(&index.to_le_bytes());
        seed[31] = 97;
        let root = SigningKey::from_bytes(&seed);
        seed[31] = 98;
        let key = SigningKey::from_bytes(&seed);
        let age = age::x25519::Identity::generate();
        let c = DeviceCredential::issue(&root, &key.verifying_key(), &age.to_public()).unwrap();
        let person = Person { root, key, age, c };
        authority.add_credential(person.c.clone());
        if index < 1000 {
            config
                .members
                .push(member(&person, vec![Capability::Read, Capability::Post]));
        } else {
            last = Some(person);
        }
    }
    config.members.sort_by_key(|member| member.identity_id);
    let signed = config.sign(&owner.key).unwrap();
    authority.apply_config(signed.clone()).unwrap();
    assert_eq!(authority.head().unwrap().members.len(), 1000);
    let message = chat(&authority, &owner);
    let parsed = message.chat().unwrap();
    assert_eq!(parsed.audience.len(), 1000);
    let recipients = parsed
        .recipient_credentials
        .iter()
        .map(|id| authority.credential(*id).unwrap().clone())
        .collect::<Vec<_>>();
    let ciphertext = crypto::seal_chat(&message, &recipients).unwrap();
    assert_eq!(
        crypto::open_record(&ciphertext, &owner.age)
            .unwrap()
            .bytes(),
        message.bytes()
    );
    let outsider = last.unwrap();
    assert!(crypto::open_record(&ciphertext, &outsider.age).is_err());
    let snapshot = authority.seal_snapshot(&owner.age.to_public()).unwrap();
    let opened = Authority::open_snapshot(
        &snapshot,
        &owner.age,
        authority.space(),
        &owner.root.verifying_key(),
        authority.stream(),
    )
    .unwrap();
    assert_eq!(opened.head_id(), authority.head_id());
    assert_eq!(opened.head().unwrap().members.len(), 1000);
    let mut oversized = advance(&config, signed.id());
    oversized
        .members
        .push(member(&outsider, vec![Capability::Read, Capability::Post]));
    oversized.members.sort_by_key(|member| member.identity_id);
    assert!(
        authority
            .apply_config(oversized.sign(&owner.key).unwrap())
            .is_err()
    );
    assert_eq!(authority.head_id(), Some(signed.id()));
}

#[test]
fn extreme_message_time_cannot_poison_admission_or_future_sends() {
    use elo_core::record::{MAX_INTEGER, next_message_time, valid_message_time_at};
    let (owner, mut authority, config) = setup();
    authority
        .apply_config(config.sign(&owner.key).unwrap())
        .unwrap();
    let mut body = chat(&authority, &owner).chat().unwrap();
    body.logical_time = MAX_INTEGER;
    let poisoned = body.sign(&owner.key).unwrap();
    assert!(authority.verify_historical(&poisoned).is_err());
    assert!(authority.admission(&poisoned, owner.c.id(), false).is_err());
    assert!(authority.admission(&poisoned, owner.c.id(), true).is_err());
    let now = 1_800_000_000_000;
    assert_eq!(next_message_time(MAX_INTEGER, now), now);
    assert_eq!(next_message_time(now + 5, now), now + 6);
    assert!(valid_message_time_at(now - 365 * 86400 * 1000, now));
    assert!(!valid_message_time_at(MAX_INTEGER, now));
    assert!(
        authority
            .prepare_chat(chat(&authority, &owner).chat().unwrap(), &owner.key)
            .is_ok()
    );
}

#[test]
fn config_rejects_duplicate_encryption_or_signing_keys() {
    for duplicate_recipient in [true, false] {
        let (owner, mut authority, mut config) = setup();
        let other_key = SigningKey::from_bytes(&[93; 32]);
        let other_age = age::x25519::Identity::generate();
        let signing = if duplicate_recipient {
            other_key.verifying_key()
        } else {
            owner.key.verifying_key()
        };
        let credential = DeviceCredential::issue(
            &owner.root,
            &signing,
            &if duplicate_recipient {
                owner.age.to_public()
            } else {
                other_age.to_public()
            },
        )
        .unwrap();
        config.members[0].credential_ids.push(credential.id());
        config.members[0].credential_ids.sort();
        authority.add_credential(credential);
        assert!(
            authority
                .apply_config(config.sign(&owner.key).unwrap())
                .is_err()
        );
    }
}
