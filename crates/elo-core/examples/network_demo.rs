//! Multiple real CLI processes, public synthetic data, two independent Replicas.
use age::secrecy::ExposeSecret;
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::SigningKey;
use elo_core::{
    crypto,
    demo::{DemoConfig, DemoCredential},
    identity::DeviceCredential,
    record::{SignedRecord, encode_hex},
    replica::ReplicaStore,
    store::{ClientStore, DeliveryTarget, LocalTime, PreparedLocalRecord, RecordMetadata},
    sync::{ChatAuthority, PeerDescriptor},
};
use std::{error::Error, fs, io::Write, path::Path, process::Command};
fn private_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut o = fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)?.write_all(bytes)
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let executable = std::env::args_os()
        .nth(1)
        .ok_or("expected path to elo CLI")?;
    let dir = tempfile::TempDir::new()?;
    let alice_root = SigningKey::from_bytes(&[10; 32]);
    let alice_key = SigningKey::from_bytes(&[11; 32]);
    let alice_age = age::x25519::Identity::generate();
    let charlie_root = SigningKey::from_bytes(&[20; 32]);
    let charlie_key = SigningKey::from_bytes(&[21; 32]);
    let charlie_age = age::x25519::Identity::generate();
    let alice = DeviceCredential::issue(
        &alice_root,
        &alice_key.verifying_key(),
        &alice_age.to_public(),
    )?;
    let charlie = DeviceCredential::issue(
        &charlie_root,
        &charlie_key.verifying_key(),
        &charlie_age.to_public(),
    )?;
    let mut credentials = vec![alice.clone(), charlie.clone()];
    credentials.sort_by_key(|c| c.id());
    let mut readers = vec![alice.identity(), charlie.identity()];
    readers.sort();
    let mut config = DemoConfig {
        v: 1,
        warning: "PUBLIC SYNTHETIC TEST ONLY; UNPROTECTED KEYS".into(),
        own_credential: alice.id(),
        age_identity: alice_age.to_string().expose_secret().to_owned(),
        space: elo_core::ids::SpaceId::from_bytes([1; 32]),
        stream: elo_core::ids::StreamId::from_bytes([2; 16]),
        config: elo_core::ids::RecordId::from_bytes([3; 32]),
        readers: readers.clone(),
        posters: readers,
        credentials: credentials
            .iter()
            .map(|c| DemoCredential {
                root_public_key: c.record().body()["root_public_key"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
                signed_record_base64: STANDARD.encode(c.record().bytes()),
            })
            .collect(),
        peers: vec![],
    };
    let mut read_peers = Vec::new();
    let mut targets = Vec::new();
    let mut servers = Vec::new();
    for i in 0..2 {
        let store = ReplicaStore::open(dir.path().join(format!("replica-{i}"))).await?;
        let mailbox = store.create_mailbox(1024 * 1024).await?;
        let listener = elo_core::http::local_listener("127.0.0.1:0".parse()?, true).await?;
        let url = format!("http://{}", listener.local_addr()?);
        let key = encode_hex(store.key().as_bytes());
        targets.push(DeliveryTarget {
            peer_id: store.peer_id(),
            mailbox_id: mailbox.mailbox_id,
        });
        config.peers.push(PeerDescriptor {
            url: url.clone(),
            signing_public_key: key.clone(),
            mailbox_id: mailbox.mailbox_id,
            read_token: None,
            write_token: Some(mailbox.write_token),
        });
        read_peers.push(PeerDescriptor {
            url,
            signing_public_key: key,
            mailbox_id: mailbox.mailbox_id,
            read_token: Some(mailbox.read_token),
            write_token: None,
        });
        servers.push(tokio::spawn(async move {
            axum::serve(listener, elo_core::http::router(store))
                .await
                .unwrap()
        }));
    }
    let loaded = config.load()?;
    let mut chat = SignedRecord::parse(include_bytes!(
        "../../../protocol/fixtures/chat-message-v1.record.bin"
    ))?
    .chat()?;
    chat.issuer_identity = alice.identity();
    chat.issuer_credential = alice.id();
    chat.space_id = config.space;
    chat.stream_id = config.stream;
    chat.config_id = config.config;
    chat.audience = config.readers.clone();
    chat.recipient_credentials = credentials.iter().map(|c| c.id()).collect();
    chat.payload.text = "PUBLIC DEMO: Alice is offline when Charlie reads this.".into();
    let record = chat.sign(&alice_key)?;
    loaded.authority.verify(&record, alice.id())?;
    let ciphertext = crypto::seal_chat(&record, &credentials)?;
    let store = ClientStore::open(dir.path().join("alice")).await?;
    store
        .commit_local_record_with_outbox(PreparedLocalRecord::new(
            record.id(),
            ciphertext,
            RecordMetadata::new(
                "chat.message",
                Some(chat.space_id),
                Some(chat.stream_id),
                Some(chat.config_id),
            )?,
            targets,
            LocalTime::from_millis(1)?,
        )?)
        .await?;
    store.close().await?;
    let alice_config = dir.path().join("alice-test.json");
    private_write(&alice_config, &serde_json::to_vec(&config)?)?;
    let run = |name: &str, path: &Path| -> Result<serde_json::Value, Box<dyn Error>> {
        let child = Command::new(&executable)
            .arg("--data-dir")
            .arg(dir.path().join(name))
            .args(["sync", "once", "--allow-insecure-fixtures", "--demo-config"])
            .arg(path)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()?;
        let pid = child.id();
        let result = child.wait_with_output()?;
        if !result.status.success() {
            return Err(
                format!("{name} failed: {}", String::from_utf8_lossy(&result.stderr)).into(),
            );
        }
        let report = serde_json::from_slice(&result.stdout)?;
        println!(
            "{name} process {pid} exited successfully: {}",
            String::from_utf8_lossy(&result.stdout).trim()
        );
        Ok(report)
    };
    let report = run("alice", &alice_config)?;
    assert_eq!(report["stored"], 2);
    let report = run("alice", &alice_config)?;
    assert_eq!(report["stored"], 0);
    println!("Alice has exited. Charlie starts now.");
    config.own_credential = charlie.id();
    config.age_identity = charlie_age.to_string().expose_secret().to_owned();
    config.peers = vec![read_peers[0].clone()];
    let charlie_config = dir.path().join("charlie-test.json");
    private_write(&charlie_config, &serde_json::to_vec(&config)?)?;
    assert_eq!(run("charlie", &charlie_config)?["accepted"], 1);
    servers[0].abort();
    config.peers = vec![read_peers[1].clone()];
    let alternate = dir.path().join("charlie-alternate-test.json");
    private_write(&alternate, &serde_json::to_vec(&config)?)?;
    assert_eq!(run("charlie", &alternate)?["accepted"], 1);
    assert_eq!(run("charlie", &alternate)?["downloaded"], 0);
    let store = ClientStore::open(dir.path().join("charlie")).await?;
    assert_eq!(store.stats().await?.records, 1);
    for id in store.message_sources().await? {
        let bytes = store.get_object(id).await?.ok_or("missing object")?;
        let received = crypto::open_record(&bytes, &charlie_age)?;
        assert_eq!(received.bytes(), record.bytes());
        loaded.authority.verify(&received, charlie.id())?;
    }
    store.close().await?;
    for server in servers {
        server.abort();
    }
    println!(
        "PASS: exact signed plaintext, one record, durable restart, alternate Replica, no Alice process online."
    );
    Ok(())
}
