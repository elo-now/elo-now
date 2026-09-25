use elo_core::{
    ids::ObjectId,
    replica::{Inventory, ReplicaError, ReplicaStore, TransferHint, VerifiedReceipt},
};
use reqwest::StatusCode;
use rusqlite::Connection;
#[tokio::test]
async fn five_lost_ack_retries_and_restart_keep_one_delivery() {
    let dir = tempfile::TempDir::new().unwrap();
    let store = ReplicaStore::open(dir.path()).await.unwrap();
    let descriptor = store.create_mailbox(1024).await.unwrap();
    let key = *store.key();
    let bytes = b"PUBLIC OPAQUE CIPHERTEXT TEST".to_vec();
    let id = ObjectId::of_ciphertext(&bytes);
    for n in 0..6 {
        let (inserted, receipt) = store
            .post(
                descriptor.mailbox_id,
                descriptor.write_token.clone(),
                id,
                bytes.clone(),
                TransferHint::Eager,
            )
            .await
            .unwrap();
        assert_eq!(inserted, n == 0);
        let receipt =
            VerifiedReceipt::verify(&receipt, &key, descriptor.mailbox_id, id, bytes.len())
                .unwrap();
        assert_eq!(receipt.body().arrival_seq, 1);
    }
    let inventory = store
        .inventory(descriptor.mailbox_id, descriptor.read_token.clone(), 0, 128)
        .await
        .unwrap();
    assert_eq!(inventory.entries.len(), 1);
    drop(store);
    let store = ReplicaStore::open(dir.path()).await.unwrap();
    assert_eq!(store.key(), &key);
    let next = store
        .inventory(descriptor.mailbox_id, descriptor.read_token.clone(), 0, 128)
        .await
        .unwrap();
    assert_eq!(next.storage_generation, inventory.storage_generation);
    assert_eq!(
        store
            .get(descriptor.mailbox_id, descriptor.read_token, id)
            .await
            .unwrap(),
        bytes
    );
}
#[tokio::test]
async fn capabilities_and_mailbox_binding_are_independent() {
    let dir = tempfile::TempDir::new().unwrap();
    let store = ReplicaStore::open(dir.path()).await.unwrap();
    let a = store.create_mailbox(1024).await.unwrap();
    let b = store.create_mailbox(1024).await.unwrap();
    let bytes = vec![4; 80];
    let id = ObjectId::of_ciphertext(&bytes);
    assert!(matches!(
        store
            .post(
                a.mailbox_id,
                a.read_token.clone(),
                id,
                bytes.clone(),
                TransferHint::Eager
            )
            .await,
        Err(ReplicaError::Unauthorized)
    ));
    store
        .post(
            a.mailbox_id,
            a.write_token.clone(),
            id,
            bytes.clone(),
            TransferHint::Eager,
        )
        .await
        .unwrap();
    assert!(matches!(
        store.get(a.mailbox_id, a.write_token, id).await,
        Err(ReplicaError::Unauthorized)
    ));
    assert!(matches!(
        store.get(b.mailbox_id, a.read_token, id).await,
        Err(ReplicaError::Unauthorized)
    ));
    assert!(matches!(
        store.get(b.mailbox_id, b.read_token.clone(), id).await,
        Err(ReplicaError::NotFound)
    ));
    assert!(
        store
            .inventory(b.mailbox_id, b.read_token, 0, 129)
            .await
            .is_err()
    );
}
#[tokio::test]
async fn bad_hash_quota_and_conflicting_mode_never_create_success() {
    let dir = tempfile::TempDir::new().unwrap();
    let store = ReplicaStore::open(dir.path()).await.unwrap();
    let d = store.create_mailbox(80).await.unwrap();
    let bytes = vec![4; 80];
    let id = ObjectId::of_ciphertext(&bytes);
    assert!(
        store
            .post(
                d.mailbox_id,
                d.write_token.clone(),
                ObjectId::from_bytes([0; 32]),
                bytes.clone(),
                TransferHint::Eager
            )
            .await
            .is_err()
    );
    assert!(matches!(
        store
            .post(
                d.mailbox_id,
                d.write_token.clone(),
                ObjectId::of_ciphertext(&[4; 81]),
                vec![4; 81],
                TransferHint::Eager
            )
            .await,
        Err(ReplicaError::Quota)
    ));
    assert!(
        store
            .inventory(d.mailbox_id, d.read_token.clone(), 0, 128)
            .await
            .unwrap()
            .entries
            .is_empty()
    );
    store
        .post(
            d.mailbox_id,
            d.write_token.clone(),
            id,
            bytes.clone(),
            TransferHint::Eager,
        )
        .await
        .unwrap();
    assert!(matches!(
        store
            .post(d.mailbox_id, d.write_token, id, bytes, TransferHint::Lazy)
            .await,
        Err(ReplicaError::Conflict)
    ));
    let raw = Connection::open(dir.path().join("replica.sqlite")).unwrap();
    assert_eq!(
        raw.query_row::<i64, _, _>("SELECT count(*) FROM objects", [], |r| r.get(0))
            .unwrap(),
        1
    );
}
#[tokio::test]
async fn delivery_failure_rolls_back_object_and_busy_never_returns_receipt() {
    let dir = tempfile::TempDir::new().unwrap();
    let store = ReplicaStore::open(dir.path()).await.unwrap();
    let d = store.create_mailbox(1024).await.unwrap();
    let raw = Connection::open(dir.path().join("replica.sqlite")).unwrap();
    raw.execute_batch("CREATE TRIGGER fail_delivery BEFORE INSERT ON deliveries BEGIN SELECT RAISE(ABORT,'injected'); END").unwrap();
    let bytes = vec![5; 80];
    let id = ObjectId::of_ciphertext(&bytes);
    assert!(
        store
            .post(
                d.mailbox_id,
                d.write_token.clone(),
                id,
                bytes.clone(),
                TransferHint::Eager
            )
            .await
            .is_err()
    );
    assert_eq!(
        raw.query_row::<i64, _, _>("SELECT count(*) FROM objects", [], |r| r.get(0))
            .unwrap(),
        0
    );
    raw.execute_batch("DROP TRIGGER fail_delivery; BEGIN IMMEDIATE")
        .unwrap();
    assert!(
        store
            .post(d.mailbox_id, d.write_token, id, bytes, TransferHint::Eager)
            .await
            .is_err()
    );
    raw.execute_batch("ROLLBACK").unwrap();
    assert!(
        store
            .inventory(d.mailbox_id, d.read_token, 0, 128)
            .await
            .unwrap()
            .entries
            .is_empty()
    );
}
#[tokio::test]
async fn replica_rejects_client_schema_and_process_lock_conflict() {
    let dir = tempfile::TempDir::new().unwrap();
    let store = ReplicaStore::open(dir.path()).await.unwrap();
    assert!(ReplicaStore::open(dir.path()).await.is_err());
    drop(store);
    let client = tempfile::TempDir::new().unwrap();
    let c = elo_core::store::ClientStore::open(client.path())
        .await
        .unwrap();
    assert!(ReplicaStore::open(client.path()).await.is_err());
    c.close().await.unwrap();
}
#[tokio::test]
async fn receipts_require_pinned_key_and_exact_delivery() {
    let dir = tempfile::TempDir::new().unwrap();
    let store = ReplicaStore::open(dir.path()).await.unwrap();
    let d = store.create_mailbox(1024).await.unwrap();
    let bytes = vec![9; 80];
    let id = ObjectId::of_ciphertext(&bytes);
    let (_, r) = store
        .post(d.mailbox_id, d.write_token, id, bytes, TransferHint::Eager)
        .await
        .unwrap();
    let wrong = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
    assert!(VerifiedReceipt::verify(&r, &wrong.verifying_key(), d.mailbox_id, id, 80).is_err());
    assert!(VerifiedReceipt::verify(&r, store.key(), d.mailbox_id, id, 81).is_err());
    assert!(
        VerifiedReceipt::verify(
            &r,
            store.key(),
            d.mailbox_id,
            ObjectId::from_bytes([0; 32]),
            80
        )
        .is_err()
    );
}
#[tokio::test]
async fn real_http_enforces_auth_retries_hash_and_limit() {
    let dir = tempfile::TempDir::new().unwrap();
    let store = ReplicaStore::open(dir.path()).await.unwrap();
    let d = store.create_mailbox(32 * 1024 * 1024).await.unwrap();
    assert!(
        elo_core::http::local_listener("0.0.0.0:0".parse().unwrap(), true)
            .await
            .is_err()
    );
    assert!(
        elo_core::http::local_listener("127.0.0.1:0".parse().unwrap(), false)
            .await
            .is_err()
    );
    let listener = elo_core::http::local_listener("127.0.0.1:0".parse().unwrap(), true)
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        {
            let origin = format!("http://{}", listener.local_addr().unwrap());
            axum::serve(listener, elo_core::http::router(store, &origin))
        }
        .await
        .unwrap()
    });
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let root = format!("http://{address}/v1/mailboxes/{}", d.mailbox_id);
    let bytes = b"PUBLIC TEST BYTES".to_vec();
    let id = ObjectId::of_ciphertext(&bytes);
    let url = format!("{root}/objects/{id}");
    assert_eq!(
        client
            .get(format!("{root}/inventory"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    for n in 0..6 {
        let r = client
            .post(&url)
            .bearer_auth(&d.write_token)
            .header("x-elo-transfer", "eager")
            .body(bytes.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(
            r.status(),
            if n == 0 {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            }
        );
    }
    assert_eq!(
        client
            .get(&url)
            .bearer_auth(&d.write_token)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        client
            .get(&url)
            .bearer_auth(&d.read_token)
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap()
            .as_ref(),
        bytes
    );
    let page: Inventory = client
        .get(format!("{root}/inventory"))
        .bearer_auth(&d.read_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(page.entries.len(), 1);
    assert_eq!(
        client
            .post(&url)
            .bearer_auth(&d.write_token)
            .header("x-elo-transfer", "eager")
            .body("changed")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        client
            .post(&url)
            .bearer_auth(&d.write_token)
            .header("x-elo-transfer", "eager")
            .body(vec![0; 16 * 1024 * 1024 + 1])
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert_eq!(
        client
            .get(format!("http://{address}/v1/mailboxes"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    server.abort();
}

#[tokio::test]
async fn expired_child_allocation_reclaims_count_and_unreferenced_ciphertext() {
    use elo_core::replica::{ChildMailbox, MailboxDescriptor};
    let dir = tempfile::tempdir().unwrap();
    let store = ReplicaStore::open(dir.path()).await.unwrap();
    let parent = store.create_mailbox(4096).await.unwrap();
    let child = MailboxDescriptor::random().unwrap();
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    store
        .create_child(
            parent.mailbox_id,
            parent.write_token.clone(),
            ChildMailbox {
                descriptor: child.clone(),
                quota_bytes: 4096,
                expires_at: time + 60000,
            },
        )
        .await
        .unwrap();
    let bytes = b"expired child ciphertext".to_vec();
    let object = ObjectId::of_ciphertext(&bytes);
    store
        .post(
            child.mailbox_id,
            child.write_token.clone(),
            object,
            bytes,
            TransferHint::Eager,
        )
        .await
        .unwrap();
    let db = Connection::open(dir.path().join("replica.sqlite")).unwrap();
    db.execute("UPDATE mailbox_delegations SET expires_at=1", [])
        .unwrap();
    let next = MailboxDescriptor::random().unwrap();
    store
        .create_child(
            parent.mailbox_id,
            parent.write_token,
            ChildMailbox {
                descriptor: next,
                quota_bytes: 4096,
                expires_at: time + 60000,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        db.query_row("SELECT count(*) FROM mailbox_delegations", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM objects", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert!(
        store
            .authorize(child.mailbox_id, child.read_token, false)
            .await
            .is_err()
    );
}
