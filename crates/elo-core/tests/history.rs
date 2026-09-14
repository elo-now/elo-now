use ed25519_dalek::SigningKey;
use elo_core::{
    authority::{Authority, Capability, ConfigAction, Member, Owner, SpaceGenesis, StreamConfig},
    history::{self, VerifiedBundle},
    identity::{DeviceCredential, VerifiedCredential},
    record::{SignedRecord, encode_hex, random_hex},
    store::{ClientStore, LocalTime},
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
fn setup() -> (Person, Person, Authority, Vec<SignedRecord>) {
    let owner = person(10);
    let reader = person(20);
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
    let genesis = SignedRecord::sign(&serde_json::to_vec(&g).unwrap(), &owner.root).unwrap();
    let mut a = Authority::new(
        genesis.bytes(),
        genesis.id().to_string().parse().unwrap(),
        &owner.root.verifying_key(),
        owner.c.clone(),
        elo_core::ids::StreamId::from_bytes([2; 16]),
    )
    .unwrap();
    let owner_member = Member {
        identity_id: owner.c.identity(),
        identity_type: "HUMAN".into(),
        root_public_key: encode_hex(owner.root.verifying_key().as_bytes()),
        capabilities: vec![
            Capability::Read,
            Capability::Post,
            Capability::ShareHistory,
            Capability::Manage,
        ],
        credential_ids: vec![owner.c.id()],
        external: false,
    };
    let mut c = StreamConfig {
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
        members: vec![owner_member],
        owner_credential_ids: vec![owner.c.id()],
        action: ConfigAction {
            operation: "create".into(),
            actor_identity: owner.c.identity(),
            request_record_id: None,
        },
    };
    a.apply_config(c.sign(&owner.key).unwrap()).unwrap();
    let mut messages = Vec::new();
    for i in 0..101 {
        let mut chat = SignedRecord::parse(include_bytes!(
            "../../../protocol/fixtures/chat-message-v1.record.bin"
        ))
        .unwrap()
        .chat()
        .unwrap();
        chat.issuer_credential = owner.c.id();
        chat.logical_time = i + 1;
        chat.nonce = format!("{i:032x}");
        chat.payload.text = format!("PUBLIC MESSAGE {i}");
        messages.push(a.prepare_chat(chat, &owner.key).unwrap());
    }
    a.add_credential(reader.c.clone());
    c.sequence = 2;
    c.previous_config_id = a.head_id();
    c.nonce = random_hex::<16>().unwrap();
    c.action.operation = "replace".into();
    c.members.push(Member {
        identity_id: reader.c.identity(),
        identity_type: "HUMAN".into(),
        root_public_key: encode_hex(reader.root.verifying_key().as_bytes()),
        capabilities: vec![Capability::Read],
        credential_ids: vec![reader.c.id()],
        external: true,
    });
    c.members.sort_by_key(|m| m.identity_id);
    a.apply_config(c.sign(&owner.key).unwrap()).unwrap();
    (owner, reader, a, messages)
}
#[test]
fn exact_hundred_excludes_unapproved_original_and_old_keys() {
    let (owner, reader, a, messages) = setup();
    let request = history::create_request(&a, reader.c.id(), 100, None, &reader.key).unwrap();
    assert!(history::create_request(&a, reader.c.id(), 101, None, &reader.key).is_err());
    assert!(history::approve(&a, &request, owner.c.id(), &messages, &owner.key).is_err());
    let grant = history::approve(&a, &request, owner.c.id(), &messages[..100], &owner.key).unwrap();
    let ciphertext = history::seal(&a, &grant).unwrap();
    let bundle =
        VerifiedBundle::open(&ciphertext, &reader.age, reader.c.id(), &a, &request).unwrap();
    assert_eq!(bundle.originals().len(), 100);
    for (i, r) in bundle.originals().iter().enumerate() {
        assert_eq!(r.bytes(), messages[i].bytes());
        assert!(!r.chat().unwrap().audience.contains(&reader.c.identity()));
    }
    assert!(
        !bundle
            .originals()
            .iter()
            .any(|r| r.id() == messages[100].id())
    );
    assert!(
        VerifiedBundle::open(
            &ciphertext,
            &age::x25519::Identity::generate(),
            reader.c.id(),
            &a,
            &request
        )
        .is_err()
    );
}
#[test]
fn requests_signatures_scope_nested_content_and_permissions_fail_closed() {
    let (owner, reader, a, messages) = setup();
    let request = history::create_request(&a, reader.c.id(), 2, None, &reader.key).unwrap();
    assert!(history::approve(&a, &request, reader.c.id(), &messages[..2], &reader.key).is_err());
    let mut wrong = messages[0].chat().unwrap();
    wrong.stream_id = elo_core::ids::StreamId::from_bytes([9; 16]);
    assert!(
        history::approve(
            &a,
            &request,
            owner.c.id(),
            &[wrong.sign(&owner.key).unwrap()],
            &owner.key
        )
        .is_err()
    );
    let mut tampered = messages[0].bytes().to_vec();
    let n = tampered.len();
    tampered[n - 1] ^= 1;
    assert!(
        history::approve(
            &a,
            &request,
            owner.c.id(),
            &[SignedRecord::parse(&tampered).unwrap()],
            &owner.key
        )
        .is_err()
    );
    let grant = history::approve(&a, &request, owner.c.id(), &messages[..2], &owner.key).unwrap();
    assert!(
        history::approve(
            &a,
            &request,
            owner.c.id(),
            std::slice::from_ref(&grant),
            &owner.key
        )
        .is_err()
    );
    let ciphertext = history::seal(&a, &grant).unwrap();
    let other_request = history::create_request(&a, reader.c.id(), 2, None, &reader.key).unwrap();
    assert!(
        VerifiedBundle::open(&ciphertext, &reader.age, reader.c.id(), &a, &other_request).is_err()
    );
}
#[tokio::test]
async fn imports_are_atomic_idempotent_and_preserve_distinct_disclosures() {
    let (owner, reader, a, messages) = setup();
    let request = history::create_request(&a, reader.c.id(), 2, None, &reader.key).unwrap();
    let grant = history::approve(&a, &request, owner.c.id(), &messages[..2], &owner.key).unwrap();
    let bytes = history::seal(&a, &grant).unwrap();
    let open = || VerifiedBundle::open(&bytes, &reader.age, reader.c.id(), &a, &request).unwrap();
    let dir = tempfile::TempDir::new().unwrap();
    let store = ClientStore::open(dir.path()).await.unwrap();
    let raw = rusqlite::Connection::open(dir.path().join("client.sqlite")).unwrap();
    raw.execute_batch("CREATE TRIGGER fail_import BEFORE INSERT ON record_sources WHEN NEW.source_index=1 BEGIN SELECT RAISE(ABORT,'injected'); END").unwrap();
    assert!(
        store
            .import_history(open(), LocalTime::from_millis(1).unwrap())
            .await
            .is_err()
    );
    assert_eq!(store.stats().await.unwrap().records, 0);
    assert_eq!(store.stats().await.unwrap().objects, 0);
    raw.execute_batch("DROP TRIGGER fail_import").unwrap();
    store
        .import_history(open(), LocalTime::from_millis(1).unwrap())
        .await
        .unwrap();
    store
        .import_history(open(), LocalTime::from_millis(2).unwrap())
        .await
        .unwrap();
    assert_eq!(
        (
            store.stats().await.unwrap().records,
            store.stats().await.unwrap().sources
        ),
        (3, 3)
    );
    let other = history::approve(&a, &request, owner.c.id(), &messages[..2], &owner.key).unwrap();
    let second = history::seal(&a, &other).unwrap();
    store
        .import_history(
            VerifiedBundle::open(&second, &reader.age, reader.c.id(), &a, &request).unwrap(),
            LocalTime::from_millis(3).unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        (
            store.stats().await.unwrap().records,
            store.stats().await.unwrap().sources
        ),
        (4, 6)
    );
    assert_eq!(
        raw.query_row::<i64, _, _>(
            "SELECT count(*) FROM records WHERE kind='chat.message'",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        2
    );
    store.close().await.unwrap();
}
#[test]
fn newer_config_quarantines_the_old_disclosure_instead_of_executing_it() {
    let (owner, reader, mut a, messages) = setup();
    let request = history::create_request(&a, reader.c.id(), 2, None, &reader.key).unwrap();
    let grant = history::approve(&a, &request, owner.c.id(), &messages[..2], &owner.key).unwrap();
    let bytes = history::seal(&a, &grant).unwrap();
    let mut config = a.head().unwrap().clone();
    config.sequence += 1;
    config.previous_config_id = a.head_id();
    config.nonce = random_hex::<16>().unwrap();
    a.apply_config(config.sign(&owner.key).unwrap()).unwrap();
    assert!(VerifiedBundle::open(&bytes, &reader.age, reader.c.id(), &a, &request).is_err());
}
