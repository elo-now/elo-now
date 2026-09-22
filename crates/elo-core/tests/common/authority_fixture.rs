use ed25519_dalek::SigningKey;
use elo_core::{
    authority::{Authority, Capability, ConfigAction, Member, Owner, SpaceGenesis, StreamConfig},
    identity::{DeviceCredential, VerifiedCredential},
    record::{SignedRecord, encode_hex, random_hex},
};
pub struct Person {
    pub root: SigningKey,
    pub key: SigningKey,
    pub age: age::x25519::Identity,
    pub c: VerifiedCredential,
}
fn person(seed: u8) -> Person {
    let root = SigningKey::from_bytes(&[seed; 32]);
    let key = SigningKey::from_bytes(&[seed + 1; 32]);
    let age = age::x25519::Identity::generate();
    let c = DeviceCredential::issue(&root, &key.verifying_key(), &age.to_public()).unwrap();
    Person { root, key, age, c }
}
pub fn setup() -> (Person, Person, Authority, Vec<SignedRecord>) {
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
            "../../../../protocol/fixtures/chat-message-v1.record.bin"
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
