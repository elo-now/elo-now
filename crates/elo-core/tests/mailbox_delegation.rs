use elo_core::{
    ids::ObjectId,
    replica::{
        ChildMailbox, MAX_CHILD_MAILBOXES, MailboxDescriptor, ReplicaError, ReplicaStore,
        TransferHint,
    },
};
use rusqlite::Connection;
fn child(quota: u64) -> ChildMailbox {
    ChildMailbox {
        descriptor: MailboxDescriptor::random().unwrap(),
        quota_bytes: quota,
        expires_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
            + 86_400_000,
    }
}
#[tokio::test]
async fn delegated_capabilities_are_isolated_and_retries_do_not_allocate_twice() {
    let dir = tempfile::TempDir::new().unwrap();
    let store = ReplicaStore::open(dir.path()).await.unwrap();
    let root = store.create_mailbox(100).await.unwrap();
    let offer = child(100);
    assert!(matches!(
        store
            .create_child(root.mailbox_id, root.read_token.clone(), offer.clone())
            .await,
        Err(ReplicaError::Unauthorized)
    ));
    store
        .create_child(root.mailbox_id, root.write_token.clone(), offer.clone())
        .await
        .unwrap();
    store
        .create_child(root.mailbox_id, root.write_token.clone(), offer.clone())
        .await
        .unwrap();
    let mut changed = offer.clone();
    changed.quota_bytes = 99;
    assert!(matches!(
        store
            .create_child(root.mailbox_id, root.write_token.clone(), changed)
            .await,
        Err(ReplicaError::Conflict)
    ));
    let mut reply = child(100);
    reply.expires_at = offer.expires_at;
    store
        .create_child(
            offer.descriptor.mailbox_id,
            offer.descriptor.write_token.clone(),
            reply.clone(),
        )
        .await
        .unwrap();
    assert!(matches!(
        store
            .create_child(
                reply.descriptor.mailbox_id,
                reply.descriptor.write_token.clone(),
                child(100)
            )
            .await,
        Err(ReplicaError::Invalid)
    ));
    for token in [
        root.read_token.clone(),
        root.write_token.clone(),
        offer.descriptor.write_token.clone(),
        reply.descriptor.read_token.clone(),
    ] {
        assert!(matches!(
            store
                .inventory(offer.descriptor.mailbox_id, token, 0, 128)
                .await,
            Err(ReplicaError::Unauthorized)
        ));
    }
    let bytes = vec![4; 80];
    let id = ObjectId::of_ciphertext(&bytes);
    store
        .post(
            reply.descriptor.mailbox_id,
            reply.descriptor.write_token.clone(),
            id,
            bytes,
            TransferHint::Eager,
        )
        .await
        .unwrap();
    for (mailbox, token) in [
        (root.mailbox_id, root.write_token),
        (offer.descriptor.mailbox_id, offer.descriptor.write_token),
    ] {
        let bytes = vec![5; 21];
        assert!(matches!(
            store
                .post(
                    mailbox,
                    token,
                    ObjectId::of_ciphertext(&bytes),
                    bytes,
                    TransferHint::Eager
                )
                .await,
            Err(ReplicaError::Quota)
        ));
    }
    drop(store);
    let store = ReplicaStore::open(dir.path()).await.unwrap();
    assert_eq!(
        store
            .inventory(
                reply.descriptor.mailbox_id,
                reply.descriptor.read_token.clone(),
                0,
                128
            )
            .await
            .unwrap()
            .entries
            .len(),
        1
    );
    let db = Connection::open(dir.path().join("replica.sqlite")).unwrap();
    db.execute(
        "UPDATE mailbox_delegations SET expires_at=1 WHERE mailbox_id=?1",
        [reply.descriptor.mailbox_id.to_string()],
    )
    .unwrap();
    assert!(matches!(
        store
            .inventory(
                reply.descriptor.mailbox_id,
                reply.descriptor.read_token,
                0,
                128
            )
            .await,
        Err(ReplicaError::Unauthorized)
    ));
}
#[tokio::test]
async fn child_count_and_lifetime_are_bounded_without_a_garbage_collector() {
    let dir = tempfile::TempDir::new().unwrap();
    let store = ReplicaStore::open(dir.path()).await.unwrap();
    let root = store.create_mailbox(1024).await.unwrap();
    let mut expired = child(10);
    expired.expires_at = 1;
    assert!(matches!(
        store
            .create_child(root.mailbox_id, root.write_token.clone(), expired)
            .await,
        Err(ReplicaError::Invalid)
    ));
    let mut too_long = child(10);
    too_long.expires_at += 100 * 86_400_000;
    assert!(matches!(
        store
            .create_child(root.mailbox_id, root.write_token.clone(), too_long)
            .await,
        Err(ReplicaError::Invalid)
    ));
    for _ in 0..MAX_CHILD_MAILBOXES {
        store
            .create_child(root.mailbox_id, root.write_token.clone(), child(10))
            .await
            .unwrap();
    }
    assert!(matches!(
        store
            .create_child(root.mailbox_id, root.write_token, child(10))
            .await,
        Err(ReplicaError::Quota)
    ));
}
#[tokio::test]
async fn recognized_v1_migrates_but_unknown_schema_is_not_modified() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("replica.sqlite");
    let db = Connection::open(&path).unwrap();
    db.execute_batch(include_str!("../../../migrations/001_replica.sql"))
        .unwrap();
    let mailbox = MailboxDescriptor::random().unwrap();
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use sha2::{Digest, Sha256};
    db.execute(
        "INSERT INTO mailboxes VALUES(?1,?2,?3,100)",
        rusqlite::params![
            mailbox.mailbox_id.to_string(),
            Sha256::digest(URL_SAFE_NO_PAD.decode(&mailbox.read_token).unwrap()).to_vec(),
            Sha256::digest(URL_SAFE_NO_PAD.decode(&mailbox.write_token).unwrap()).to_vec()
        ],
    )
    .unwrap();
    drop(db);
    let store = ReplicaStore::open(dir.path()).await.unwrap();
    store
        .inventory(mailbox.mailbox_id, mailbox.read_token, 0, 128)
        .await
        .unwrap();
    drop(store);
    let db = Connection::open(&path).unwrap();
    assert_eq!(
        db.pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
            .unwrap(),
        7
    );
    db.execute_batch("CREATE TABLE unexpected(id TEXT);")
        .unwrap();
    drop(db);
    assert!(matches!(
        ReplicaStore::open(dir.path()).await,
        Err(ReplicaError::Directory)
    ));
}
