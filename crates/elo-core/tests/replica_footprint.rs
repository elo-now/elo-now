//! Reproducible synthetic wire-size comparison, never production profile data.
#[allow(dead_code)]
mod common;
use common::{Person, authority, message};
use ed25519_dalek::SigningKey;
use elo_core::{crypto, erasure, identity::DeviceCredential};
use serde_json::json;

fn people(count: u32) -> Vec<Person> {
    (0..count)
        .map(|index| {
            let mut seed = [0; 32];
            seed[..4].copy_from_slice(&index.to_be_bytes());
            seed[31] = 1;
            let root = SigningKey::from_bytes(&seed);
            seed[31] = 2;
            let key = SigningKey::from_bytes(&seed);
            let age = age::x25519::Identity::generate();
            let credential =
                DeviceCredential::issue(&root, &key.verifying_key(), &age.to_public()).unwrap();
            Person {
                key,
                age,
                credential,
            }
        })
        .collect()
}

#[test]
#[ignore = "synthetic recipient scaling measurement"]
fn measure_chat_storage_by_recipient_count() {
    let mut measurements = Vec::new();
    for count in [2u32, 100, 1000] {
        let people = people(count);
        let authority = authority(&people.iter().collect::<Vec<_>>());
        let record = message(&people[0], &authority);
        let credentials: Vec<_> = authority.credentials.values().cloned().collect();
        let keys: Vec<_> = credentials.iter().map(|c| c.recipient()).collect();
        let raw = crypto::seal_record(&record, &keys).unwrap();
        let packed = crypto::seal_chat(&record, &credentials).unwrap();
        let raw_owned = erasure::wrap(raw.clone(), &people[0].credential, &people[0].key).unwrap();
        let packed_owned =
            erasure::wrap(packed.clone(), &people[0].credential, &people[0].key).unwrap();
        for person in [&people[0], &people[people.len() - 1]] {
            let opened = crypto::open_object(&packed_owned, &person.age).unwrap();
            assert_eq!(opened.bytes(), record.bytes());
            opened
                .verify_signature(&people[0].key.verifying_key())
                .unwrap();
        }
        measurements.push(json!({
            "recipients": count, "message_text_utf8_bytes": record.chat().unwrap().payload.text.len(), "signed_record_bytes": record.bytes().len(),
            "legacy_age_bytes": raw.len(), "packed_age_bytes": packed.len(),
            "legacy_owned_bytes": raw_owned.len(), "packed_owned_bytes": packed_owned.len(),
            "outer_envelope_bytes": raw_owned.len() - raw.len(),
            "credential_record_bytes": people[0].credential.record().bytes().len(),
            "saved_bytes": raw_owned.len() - packed_owned.len(),
        }));
    }
    println!(
        "{}",
        serde_json::to_string(&json!({"measurements": measurements})).unwrap()
    );
}

#[tokio::test]
#[ignore = "synthetic SQLite footprint comparison"]
async fn measure_sqlite_storage_for_one_hundred_messages() {
    use elo_core::{
        ids::ObjectId,
        replica::{ReplicaStore, TransferHint},
    };
    use rusqlite::{Connection, params};
    let dir = tempfile::tempdir().unwrap();
    let people = people(100);
    let authority = authority(&people.iter().collect::<Vec<_>>());
    let mut chat = message(&people[0], &authority).chat().unwrap();
    let credentials: Vec<_> = authority.credentials.values().cloned().collect();
    let keys: Vec<_> = credentials.iter().map(|c| c.recipient()).collect();
    let legacy_path = dir.path().join("legacy.sqlite");
    let legacy = Connection::open(&legacy_path).unwrap();
    for migration in [
        include_str!("../../../migrations/001_replica.sql"),
        include_str!("../../../migrations/002_replica_mailbox_delegation.sql"),
        include_str!("../../../migrations/003_replica_space_access.sql"),
        include_str!("../../../migrations/004_replica_retention.sql"),
        include_str!("../../../migrations/005_replica_account_erasure.sql"),
    ] {
        legacy.execute_batch(migration).unwrap();
    }
    legacy
        .execute_batch("PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")
        .unwrap();
    let current = ReplicaStore::open(dir.path().join("current"))
        .await
        .unwrap();
    let descriptor = current.create_mailbox(16 * 1024 * 1024).await.unwrap();
    let mailbox = descriptor.mailbox_id.to_string();
    legacy
        .execute(
            "INSERT INTO mailboxes VALUES(?1,?2,?3,?4)",
            params![mailbox, vec![1u8; 32], vec![2u8; 32], 16 * 1024 * 1024],
        )
        .unwrap();
    let mut legacy_wire = 0;
    let mut current_wire = 0;
    for index in 1..=100u64 {
        chat.logical_time = index;
        let signed = chat.sign(&people[0].key).unwrap();
        let before = erasure::wrap(
            crypto::seal_record(&signed, &keys).unwrap(),
            &people[0].credential,
            &people[0].key,
        )
        .unwrap();
        let after = erasure::wrap(
            crypto::seal_chat(&signed, &credentials).unwrap(),
            &people[0].credential,
            &people[0].key,
        )
        .unwrap();
        legacy_wire += before.len();
        current_wire += after.len();
        let id = ObjectId::of_ciphertext(&before).to_string();
        legacy.execute_batch("BEGIN IMMEDIATE;").unwrap();
        legacy
            .execute(
                "INSERT INTO objects VALUES(?1,?2,?3,1)",
                params![id, before, before.len() as i64],
            )
            .unwrap();
        legacy
            .execute(
                "INSERT INTO deliveries(mailbox_id,object_id,transfer_hint) VALUES(?1,?2,'eager')",
                params![mailbox, id],
            )
            .unwrap();
        legacy
            .execute(
                "INSERT INTO object_owners VALUES(?1,?2)",
                params![id, people[0].credential.identity().to_string()],
            )
            .unwrap();
        legacy
            .execute(
                "INSERT INTO message_copies VALUES(?1,?2,1)",
                params![mailbox, id],
            )
            .unwrap();
        legacy.execute_batch("COMMIT;").unwrap();
        let id = ObjectId::of_ciphertext(&after);
        current
            .post_classified(
                descriptor.mailbox_id,
                descriptor.write_token.clone(),
                id,
                after.clone(),
                TransferHint::Eager,
                true,
            )
            .await
            .unwrap();
        assert_eq!(
            current
                .get(descriptor.mailbox_id, descriptor.read_token.clone(), id)
                .await
                .unwrap(),
            after
        );
    }
    legacy
        .execute_batch("VACUUM; PRAGMA wal_checkpoint(TRUNCATE);")
        .unwrap();
    current.compact_storage().await.unwrap();
    let current_path = dir.path().join("current/replica.sqlite");
    let packed_db = Connection::open(&current_path).unwrap();
    let (compact_objects, credentials_bytes): (i64,i64) = packed_db.query_row("SELECT SUM(size_bytes),(SELECT SUM(length(encoded)) FROM object_credentials) FROM objects", [], |r|Ok((r.get(0)?,r.get(1)?))).unwrap();
    let before = std::fs::metadata(&legacy_path).unwrap().len();
    let after = std::fs::metadata(&current_path).unwrap().len();
    assert!(after < before);
    println!(
        "{}",
        json!({"sqlite": {
            "messages":100, "recipients":100, "senders":1,
            "legacy_wire_bytes":legacy_wire, "packed_wire_bytes":current_wire,
            "legacy_database_bytes":before,"packed_database_bytes":after,
            "interned_object_bytes":compact_objects,"credential_bytes":credentials_bytes,
            "legacy_page_size":legacy.query_row::<i64,_,_>("PRAGMA page_size",[],|r|r.get(0)).unwrap(),
            "packed_page_size":packed_db.query_row::<i64,_,_>("PRAGMA page_size",[],|r|r.get(0)).unwrap()
        }})
    );
}
