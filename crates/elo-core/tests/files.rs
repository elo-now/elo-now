#[path = "common/authority_fixture.rs"]
mod fixture;
use elo_core::{
    files::{self, VerifiedFileShare},
    record::encode_hex,
    replica::{ReplicaStore, TransferHint},
    store::{ClientStore, DeliveryTarget, LocalTime},
    sync::{Peer, PeerDescriptor, SyncClient},
};
#[test]
fn maximum_file_round_trips_and_oversize_or_unsafe_metadata_fails() {
    let (owner, reader, a, _) = fixture::setup();
    let bytes = vec![0xa5; files::MAX_FILE];
    let file = files::prepare(
        &a,
        owner.c.id(),
        "sample.bin",
        "application/octet-stream",
        &bytes,
        &owner.key,
    )
    .unwrap();
    let share = VerifiedFileShare::verify(&file.shared, &a, reader.c.id(), false).unwrap();
    assert_eq!(
        files::open(&file.ciphertext, &reader.age, reader.c.id(), &share, &a)
            .unwrap()
            .bytes,
        bytes
    );
    assert!(
        files::prepare(
            &a,
            owner.c.id(),
            "sample.bin",
            "application/octet-stream",
            &vec![0; files::MAX_FILE + 1],
            &owner.key
        )
        .is_err()
    );
    for name in ["../secret", "a/b", "a\\b", ".", "..", "bad\nname"] {
        assert!(files::prepare(&a, owner.c.id(), name, "text/plain", b"text", &owner.key).is_err());
    }
    assert!(
        files::prepare(
            &a,
            reader.c.id(),
            "x.txt",
            "text/plain",
            b"text",
            &reader.key
        )
        .is_err()
    );
}
#[test]
fn corrupted_wrong_resource_wrong_key_and_history_inclusion_are_rejected() {
    let (owner, reader, a, _) = fixture::setup();
    let file = files::prepare(
        &a,
        owner.c.id(),
        "hello.txt",
        "text/plain",
        b"PUBLIC FILE",
        &owner.key,
    )
    .unwrap();
    let share = VerifiedFileShare::verify(&file.shared, &a, reader.c.id(), false).unwrap();
    let mut bytes = file.ciphertext.clone();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    assert!(files::open(&bytes, &reader.age, reader.c.id(), &share, &a).is_err());
    assert!(
        files::open(
            &file.ciphertext,
            &age::x25519::Identity::generate(),
            reader.c.id(),
            &share,
            &a
        )
        .is_err()
    );
    let mut shared = file.shared.body().clone();
    shared["resource_id"] = serde_json::json!("ff".repeat(16));
    let wrong =
        elo_core::record::SignedRecord::sign(&serde_json::to_vec(&shared).unwrap(), &owner.key)
            .unwrap();
    let wrong = VerifiedFileShare::verify(&wrong, &a, reader.c.id(), false).unwrap();
    assert!(files::open(&file.ciphertext, &reader.age, reader.c.id(), &wrong, &a).is_err());
    let request =
        elo_core::history::create_request(&a, reader.c.id(), 1, None, &reader.key).unwrap();
    assert!(
        elo_core::history::approve(&a, &request, owner.c.id(), &[file.shared], &owner.key).is_err()
    );
}
#[tokio::test]
async fn normal_sync_fetches_only_metadata_then_explicit_download_verifies_the_file() {
    let (owner, reader, a, _) = fixture::setup();
    let content = b"PUBLIC FILE ONLY AFTER CLICK";
    let file = files::prepare(
        &a,
        owner.c.id(),
        "hello.txt",
        "text/plain",
        content,
        &owner.key,
    )
    .unwrap();
    let share = VerifiedFileShare::verify(&file.shared, &a, reader.c.id(), false).unwrap();
    let expected_size = file.ciphertext.len() as u64;
    let rd = tempfile::TempDir::new().unwrap();
    let replica = ReplicaStore::open(rd.path()).await.unwrap();
    let mailbox = replica.create_mailbox(1024 * 1024).await.unwrap();
    let listener = elo_core::http::local_listener("127.0.0.1:0".parse().unwrap(), true)
        .await
        .unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let key = encode_hex(replica.key().as_bytes());
    let remote = replica.clone();
    let server = tokio::spawn(async move {
        {
            let origin = format!("http://{}", listener.local_addr().unwrap());
            axum::serve(listener, elo_core::http::router(remote, &origin))
        }
        .await
        .unwrap()
    });
    let make = |read, write| {
        Peer::new(
            PeerDescriptor {
                url: url.clone(),
                signing_public_key: key.clone(),
                mailbox_id: mailbox.mailbox_id,
                read_token: if read {
                    Some(mailbox.read_token.clone())
                } else {
                    None
                },
                write_token: if write {
                    Some(mailbox.write_token.clone())
                } else {
                    None
                },
            },
            true,
        )
        .unwrap()
    };
    let writers = [make(false, true)];
    let readers = [make(true, false)];
    let ad = tempfile::TempDir::new().unwrap();
    let alice = ClientStore::open(ad.path()).await.unwrap();
    alice
        .commit_file(
            file,
            vec![DeliveryTarget {
                peer_id: writers[0].id(),
                mailbox_id: mailbox.mailbox_id,
            }],
            LocalTime::from_millis(1).unwrap(),
        )
        .await
        .unwrap();
    let report = SyncClient {
        store: &alice,
        identity: &owner.age,
        credential: owner.c.id(),
        authority: &a,
        peers: &writers,
    }
    .once(LocalTime::from_millis(2).unwrap())
    .await
    .unwrap();
    assert_eq!(report.stored, 2);
    alice.close().await.unwrap();
    let page = replica
        .inventory(mailbox.mailbox_id, mailbox.read_token.clone(), 0, 128)
        .await
        .unwrap();
    assert_eq!(
        page.entries
            .iter()
            .filter(|e| e.transfer_hint == TransferHint::Lazy)
            .count(),
        1
    );
    let bd = tempfile::TempDir::new().unwrap();
    let bob = ClientStore::open(bd.path()).await.unwrap();
    let report = SyncClient {
        store: &bob,
        identity: &reader.age,
        credential: reader.c.id(),
        authority: &a,
        peers: &readers,
    }
    .once(LocalTime::from_millis(3).unwrap())
    .await
    .unwrap();
    assert_eq!(
        (report.downloaded, report.accepted, report.deferred),
        (1, 1, 1)
    );
    assert!(
        bob.get_object(share.body().object_id.unwrap())
            .await
            .unwrap()
            .is_none()
    );
    let ciphertext = readers[0]
        .get(share.body().object_id.unwrap(), expected_size)
        .await
        .unwrap();
    let verified = files::open(&ciphertext, &reader.age, reader.c.id(), &share, &a).unwrap();
    assert_eq!(verified.bytes, content);
    assert!(
        readers[0]
            .get(elo_core::ids::ObjectId::from_bytes([0; 32]), expected_size)
            .await
            .is_err()
    );
    bob.close().await.unwrap();
    server.abort();
}
