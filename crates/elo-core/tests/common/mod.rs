use ed25519_dalek::SigningKey;
use elo_core::{
    identity::{DeviceCredential, VerifiedCredential},
    record::{ChatMessage, SignedRecord},
    replica::ReplicaStore,
    sync::{FixedDemoAuthority, Peer, PeerDescriptor},
};
pub struct Person {
    pub key: SigningKey,
    pub age: age::x25519::Identity,
    pub credential: VerifiedCredential,
}
pub fn person(seed: u8) -> Person {
    let root = SigningKey::from_bytes(&[seed; 32]);
    let key = SigningKey::from_bytes(&[seed + 1; 32]);
    let age = age::x25519::Identity::generate();
    let credential =
        DeviceCredential::issue(&root, &key.verifying_key(), &age.to_public()).unwrap();
    Person {
        key,
        age,
        credential,
    }
}
pub fn authority(people: &[&Person]) -> FixedDemoAuthority {
    FixedDemoAuthority {
        space: elo_core::ids::SpaceId::from_bytes([1; 32]),
        stream: elo_core::ids::StreamId::from_bytes([2; 16]),
        config: elo_core::ids::RecordId::from_bytes([3; 32]),
        readers: people.iter().map(|p| p.credential.identity()).collect(),
        posters: people.iter().map(|p| p.credential.identity()).collect(),
        credentials: people
            .iter()
            .map(|p| (p.credential.id(), p.credential.clone()))
            .collect(),
    }
}
pub fn message(author: &Person, authority: &FixedDemoAuthority) -> SignedRecord {
    let mut chat: ChatMessage = SignedRecord::parse(include_bytes!(
        "../../../../protocol/fixtures/chat-message-v1.record.bin"
    ))
    .unwrap()
    .chat()
    .unwrap();
    chat.issuer_identity = author.credential.identity();
    chat.issuer_credential = author.credential.id();
    chat.space_id = authority.space;
    chat.stream_id = authority.stream;
    chat.config_id = authority.config;
    chat.audience = authority.readers.iter().copied().collect();
    chat.recipient_credentials = authority.credentials.keys().copied().collect();
    chat.sign(&author.key).unwrap()
}
pub async fn server(store: ReplicaStore) -> (String, tokio::task::JoinHandle<()>) {
    let listener = elo_core::http::local_listener("127.0.0.1:0".parse().unwrap(), true)
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        {
            let origin = format!("http://{}", listener.local_addr().unwrap());
            axum::serve(listener, elo_core::http::router(store, &origin))
        }
        .await
        .unwrap();
    });
    (format!("http://{address}"), task)
}
pub fn peer(
    url: &str,
    store: &ReplicaStore,
    descriptor: &elo_core::replica::MailboxDescriptor,
    read: bool,
    write: bool,
) -> Peer {
    Peer::new(
        PeerDescriptor {
            url: url.into(),
            signing_public_key: elo_core::record::encode_hex(store.key().as_bytes()),
            mailbox_id: descriptor.mailbox_id,
            read_token: read.then(|| descriptor.read_token.clone()),
            write_token: write.then(|| descriptor.write_token.clone()),
        },
        true,
    )
    .unwrap()
}
