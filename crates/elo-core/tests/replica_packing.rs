#[allow(dead_code)]
mod common;
use common::*;
use elo_core::{
    crypto, erasure,
    ids::ObjectId,
    replica::{ReplicaError, ReplicaStore, TransferHint, VerifiedReceipt},
};
use rusqlite::{Connection, params};

fn scalar(c: &Connection, sql: &str) -> i64 {
    c.query_row(sql, [], |r| r.get(0)).unwrap()
}

#[tokio::test]
async fn interning_preserves_hashes_receipts_quota_scope_and_restart_then_collects_credentials() {
    let dir = tempfile::tempdir().unwrap();
    let store = ReplicaStore::open(dir.path()).await.unwrap();
    let alice = person(3);
    let bob = person(7);
    let authority = authority(&[&alice, &bob]);
    let record = message(&alice, &authority);
    let recipients: Vec<_> = authority.credentials.values().cloned().collect();
    let mut objects = Vec::new();
    for _ in 0..4 {
        let cipher = crypto::seal_chat(&record, &recipients).unwrap();
        objects.push(erasure::wrap(cipher, &alice.credential, &alice.key).unwrap());
    }
    let total: usize = objects.iter().map(Vec::len).sum();
    let a = store.create_mailbox(total as u64).await.unwrap();
    let b = store.create_mailbox(total as u64).await.unwrap();
    let key = *store.key();
    for bytes in &objects {
        let id = ObjectId::of_ciphertext(bytes);
        let (inserted, receipt) = store
            .post(
                a.mailbox_id,
                a.write_token.clone(),
                id,
                bytes.clone(),
                TransferHint::Eager,
            )
            .await
            .unwrap();
        assert!(inserted);
        VerifiedReceipt::verify(&receipt, &key, a.mailbox_id, id, bytes.len()).unwrap();
        assert!(
            !store
                .post(
                    a.mailbox_id,
                    a.write_token.clone(),
                    id,
                    bytes.clone(),
                    TransferHint::Eager
                )
                .await
                .unwrap()
                .0
        );
        assert!(matches!(
            store.get(b.mailbox_id, b.read_token.clone(), id).await,
            Err(ReplicaError::NotFound)
        ));
    }
    let extra = erasure::wrap(
        crypto::seal_chat(&record, &recipients).unwrap(),
        &alice.credential,
        &alice.key,
    )
    .unwrap();
    assert!(matches!(
        store
            .post(
                a.mailbox_id,
                a.write_token.clone(),
                ObjectId::of_ciphertext(&extra),
                extra,
                TransferHint::Eager
            )
            .await,
        Err(ReplicaError::Quota)
    ));
    let raw = Connection::open(dir.path().join("replica.sqlite")).unwrap();
    assert_eq!(scalar(&raw, "SELECT COUNT(*) FROM object_credentials"), 1);
    assert_eq!(
        scalar(
            &raw,
            "SELECT COUNT(*) FROM objects WHERE credential_id IS NOT NULL"
        ),
        4
    );
    let physical = scalar(
        &raw,
        "SELECT SUM(size_bytes)+(SELECT SUM(length(encoded)) FROM object_credentials) FROM objects",
    );
    assert!(physical < total as i64);
    assert!(
        raw.execute("UPDATE objects SET credential_offset=0", [])
            .is_err()
    );
    assert!(
        raw.execute("UPDATE object_credentials SET encoded=x'00'", [])
            .is_err()
    );
    assert_eq!(
        store
            .space_storage(a.mailbox_id, 0)
            .await
            .unwrap()
            .used_bytes,
        total as u64
    );
    let before = store
        .inventory(a.mailbox_id, a.read_token.clone(), 0, 128)
        .await
        .unwrap();
    assert_eq!(
        before
            .entries
            .iter()
            .map(|entry| entry.size_bytes)
            .sum::<u64>(),
        total as u64
    );
    drop(raw);
    drop(store);
    let store = ReplicaStore::open(dir.path()).await.unwrap();
    store.compact_storage().await.unwrap();
    let after = store
        .inventory(a.mailbox_id, a.read_token.clone(), 0, 128)
        .await
        .unwrap();
    assert_eq!(before.storage_generation, after.storage_generation);
    assert_eq!(store.key(), &key);
    for bytes in &objects {
        let retrieved = store
            .get(
                a.mailbox_id,
                a.read_token.clone(),
                ObjectId::of_ciphertext(bytes),
            )
            .await
            .unwrap();
        assert_eq!(&retrieved, bytes);
        assert_eq!(
            crypto::open_record(&retrieved, &bob.age).unwrap().bytes(),
            record.bytes()
        );
    }
    let bytes = objects[0].clone();
    store
        .post(
            b.mailbox_id,
            b.write_token.clone(),
            ObjectId::of_ciphertext(&bytes),
            bytes.clone(),
            TransferHint::Eager,
        )
        .await
        .unwrap();
    store.delete_mailbox_tree(a.mailbox_id).await.unwrap();
    assert_eq!(
        store
            .get(
                b.mailbox_id,
                b.read_token.clone(),
                ObjectId::of_ciphertext(&bytes)
            )
            .await
            .unwrap(),
        bytes
    );
    let raw = Connection::open(dir.path().join("replica.sqlite")).unwrap();
    assert_eq!(scalar(&raw, "SELECT COUNT(*) FROM object_credentials"), 1);
    store.delete_mailbox_tree(b.mailbox_id).await.unwrap();
    assert_eq!(scalar(&raw, "SELECT COUNT(*) FROM object_credentials"), 0);
    assert_eq!(
        scalar(&raw, "SELECT COUNT(*) FROM pragma_foreign_key_check"),
        0
    );
}

#[tokio::test]
async fn legacy_schema_migrates_without_rewriting_objects_or_rotating_node_identity() {
    for version in 1..=5 {
        let dir = tempfile::tempdir().unwrap();
        let raw = Connection::open(dir.path().join("replica.sqlite")).unwrap();
        for migration in [
            include_str!("../../../migrations/001_replica.sql"),
            include_str!("../../../migrations/002_replica_mailbox_delegation.sql"),
            include_str!("../../../migrations/003_replica_space_access.sql"),
            include_str!("../../../migrations/004_replica_retention.sql"),
            include_str!("../../../migrations/005_replica_account_erasure.sql"),
        ]
        .iter()
        .take(version)
        {
            raw.execute_batch(migration).unwrap();
        }
        let bytes = b"LEGACY OPAQUE OBJECT";
        let id = ObjectId::of_ciphertext(bytes);
        raw.execute(
            "INSERT INTO objects VALUES(?1,?2,?3,1)",
            params![id.to_string(), bytes, bytes.len() as i64],
        )
        .unwrap();
        raw.execute(
            "INSERT INTO node_meta VALUES('signing_seed',?1),('storage_generation',?2)",
            params!["01".repeat(32), "02".repeat(32)],
        )
        .unwrap();
        drop(raw);
        let store = ReplicaStore::open(dir.path()).await.unwrap();
        let descriptor = store.create_mailbox(100_000).await.unwrap();
        store
            .post(
                descriptor.mailbox_id,
                descriptor.write_token.clone(),
                id,
                bytes.to_vec(),
                TransferHint::Eager,
            )
            .await
            .unwrap();
        let inventory = store
            .inventory(descriptor.mailbox_id, descriptor.read_token.clone(), 0, 128)
            .await
            .unwrap();
        assert_eq!(inventory.storage_generation, "02".repeat(32));
        assert_eq!(
            store.key(),
            &ed25519_dalek::SigningKey::from_bytes(&[1; 32]).verifying_key()
        );
        store.compact_storage().await.unwrap();
        assert_eq!(
            store
                .get(descriptor.mailbox_id, descriptor.read_token.clone(), id)
                .await
                .unwrap(),
            bytes
        );
        let raw = Connection::open(dir.path().join("replica.sqlite")).unwrap();
        assert_eq!(scalar(&raw, "PRAGMA user_version"), 9);
        assert_eq!(scalar(&raw, "PRAGMA auto_vacuum"), 2);
        assert_eq!(scalar(&raw, "SELECT COUNT(*) FROM object_credentials"), 0);
        assert_eq!(
            scalar(&raw, "SELECT COUNT(*) FROM pragma_foreign_key_check"),
            0
        );
    }
}

#[tokio::test]
async fn cleanup_returns_pages_to_the_filesystem_without_removing_live_objects() {
    let dir = tempfile::tempdir().unwrap();
    let store = ReplicaStore::open(dir.path()).await.unwrap();
    let a = store.create_mailbox(8 * 1024 * 1024).await.unwrap();
    let b = store.create_mailbox(1000).await.unwrap();
    let keep = b"KEEP THIS OBJECT".to_vec();
    let keep_id = ObjectId::of_ciphertext(&keep);
    store
        .post(
            b.mailbox_id,
            b.write_token.clone(),
            keep_id,
            keep.clone(),
            TransferHint::Eager,
        )
        .await
        .unwrap();
    let large = vec![7; 2 * 1024 * 1024];
    store
        .post(
            a.mailbox_id,
            a.write_token.clone(),
            ObjectId::of_ciphertext(&large),
            large,
            TransferHint::Eager,
        )
        .await
        .unwrap();
    let path = dir.path().join("replica.sqlite");
    let raw = Connection::open(&path).unwrap();
    raw.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .unwrap();
    assert_eq!(scalar(&raw, "PRAGMA auto_vacuum"), 2);
    let before = std::fs::metadata(&path).unwrap().len();
    store.delete_mailbox_tree(a.mailbox_id).await.unwrap();
    let after = std::fs::metadata(&path).unwrap().len();
    assert!(
        before - after > 1024 * 1024,
        "before={before}, after={after}"
    );
    assert_eq!(
        store
            .get(b.mailbox_id, b.read_token, keep_id)
            .await
            .unwrap(),
        keep
    );
    assert_eq!(
        scalar(&raw, "SELECT COUNT(*) FROM pragma_foreign_key_check"),
        0
    );
}

#[tokio::test]
async fn failed_delivery_rolls_back_shared_credentials_and_corruption_never_returns_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let store = ReplicaStore::open(dir.path()).await.unwrap();
    let mailbox = store.create_mailbox(100_000).await.unwrap();
    let alice = person(21);
    let record = message(&alice, &authority(&[&alice]));
    let cipher = crypto::seal_chat(&record, std::slice::from_ref(&alice.credential)).unwrap();
    let bytes = erasure::wrap(cipher, &alice.credential, &alice.key).unwrap();
    let id = ObjectId::of_ciphertext(&bytes);
    let raw = Connection::open(dir.path().join("replica.sqlite")).unwrap();
    raw.execute_batch("CREATE TRIGGER fail_delivery BEFORE INSERT ON deliveries BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
    assert!(
        store
            .post(
                mailbox.mailbox_id,
                mailbox.write_token.clone(),
                id,
                bytes.clone(),
                TransferHint::Eager
            )
            .await
            .is_err()
    );
    assert_eq!(scalar(&raw, "SELECT COUNT(*) FROM object_credentials"), 0);
    assert_eq!(scalar(&raw, "SELECT COUNT(*) FROM objects"), 0);
    raw.execute_batch("DROP TRIGGER fail_delivery;").unwrap();
    store
        .post(
            mailbox.mailbox_id,
            mailbox.write_token.clone(),
            id,
            bytes.clone(),
            TransferHint::Eager,
        )
        .await
        .unwrap();
    // Simulate external database corruption, not an authorized API mutation.
    raw.execute_batch("DROP TRIGGER object_credentials_no_update; UPDATE object_credentials SET encoded=zeroblob(length(encoded));").unwrap();
    assert!(matches!(
        store.get(mailbox.mailbox_id, mailbox.read_token, id).await,
        Err(ReplicaError::Storage)
    ));
    assert!(
        store
            .post(
                mailbox.mailbox_id,
                mailbox.write_token,
                id,
                bytes,
                TransferHint::Eager
            )
            .await
            .is_err()
    );
}

#[tokio::test]
async fn noncanonical_valid_owner_json_is_stored_without_modifying_its_signature() {
    use elo_core::record::SignedRecord;
    let dir = tempfile::tempdir().unwrap();
    let store = ReplicaStore::open(dir.path()).await.unwrap();
    let mailbox = store.create_mailbox(100_000).await.unwrap();
    let alice = person(31);
    let record = message(&alice, &authority(&[&alice]));
    let cipher = crypto::seal_chat(&record, std::slice::from_ref(&alice.credential)).unwrap();
    let original = erasure::wrap(cipher.clone(), &alice.credential, &alice.key).unwrap();
    let magic = b"elo-owned-object-v1\n";
    let start = magic.len() + 4;
    let length = u32::from_be_bytes(original[magic.len()..start].try_into().unwrap()) as usize;
    let proof = SignedRecord::parse(&original[start..start + length]).unwrap();
    let pretty = SignedRecord::sign(
        &serde_json::to_vec_pretty(proof.body()).unwrap(),
        &alice.key,
    )
    .unwrap();
    let mut bytes = magic.to_vec();
    bytes.extend_from_slice(&(pretty.bytes().len() as u32).to_be_bytes());
    bytes.extend_from_slice(pretty.bytes());
    bytes.extend_from_slice(&cipher);
    assert!(erasure::inspect(&bytes).unwrap().is_some());
    let id = ObjectId::of_ciphertext(&bytes);
    store
        .post(
            mailbox.mailbox_id,
            mailbox.write_token,
            id,
            bytes.clone(),
            TransferHint::Eager,
        )
        .await
        .unwrap();
    let retrieved = store
        .get(mailbox.mailbox_id, mailbox.read_token, id)
        .await
        .unwrap();
    assert_eq!(bytes, retrieved);
    assert_eq!(
        crypto::open_record(&retrieved, &alice.age).unwrap().bytes(),
        record.bytes()
    );
    let raw = Connection::open(dir.path().join("replica.sqlite")).unwrap();
    assert_eq!(scalar(&raw, "SELECT COUNT(*) FROM object_credentials"), 0);
}
