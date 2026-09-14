mod common;
use common::*;
use elo_core::{
    crypto,
    ids::ObjectId,
    record::{ChatMessage, SignedRecord},
    replica::{MailboxDescriptor, ReplicaStore, TransferHint},
    store::{ClientStore, DeliveryTarget, LocalTime, PreparedLocalRecord, RecordMetadata},
    sync::{FixedDemoAuthority, Peer, SyncClient, SyncReport},
};
use rusqlite::{Connection, params};

struct Node {
    dir: tempfile::TempDir,
    store: ReplicaStore,
    mailbox: MailboxDescriptor,
    url: String,
    task: tokio::task::JoinHandle<()>,
}
impl Node {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = ReplicaStore::open(dir.path()).await.unwrap();
        let mailbox = store.create_mailbox(16 * 1024 * 1024).await.unwrap();
        let (url, task) = server(store.clone()).await;
        Self {
            dir,
            store,
            mailbox,
            url,
            task,
        }
    }
    fn peer(&self, read: bool, write: bool) -> Peer {
        peer(&self.url, &self.store, &self.mailbox, read, write)
    }
    fn target(&self) -> DeliveryTarget {
        DeliveryTarget {
            peer_id: self.store.peer_id(),
            mailbox_id: self.mailbox.mailbox_id,
        }
    }
    async fn post(&self, bytes: &[u8], hint: TransferHint) {
        self.store
            .post(
                self.mailbox.mailbox_id,
                self.mailbox.write_token.clone(),
                ObjectId::of_ciphertext(bytes),
                bytes.to_vec(),
                hint,
            )
            .await
            .unwrap();
    }
    async fn mutate(self, sql: &str) -> Self {
        // Destructive fault injection is confined to a private test TempDir,
        // with the HTTP server stopped and all store handles dropped.
        self.task.abort();
        let _ = self.task.await;
        drop(self.store);
        let raw = Connection::open(self.dir.path().join("replica.sqlite")).unwrap();
        raw.execute_batch(sql).unwrap();
        drop(raw);
        let store = ReplicaStore::open(self.dir.path()).await.unwrap();
        let (url, task) = server(store.clone()).await;
        Self {
            dir: self.dir,
            store,
            mailbox: self.mailbox,
            url,
            task,
        }
    }
    async fn inventory(&self) -> elo_core::replica::Inventory {
        self.store
            .inventory(
                self.mailbox.mailbox_id,
                self.mailbox.read_token.clone(),
                0,
                128,
            )
            .await
            .unwrap()
    }
    async fn contains(&self, bytes: &[u8]) -> bool {
        self.store
            .get(
                self.mailbox.mailbox_id,
                self.mailbox.read_token.clone(),
                ObjectId::of_ciphertext(bytes),
            )
            .await
            .is_ok_and(|b| b == bytes)
    }
    async fn stop(self) {
        self.task.abort();
        let _ = self.task.await;
    }
}
fn time(ms: u64) -> LocalTime {
    LocalTime::from_millis(ms).unwrap()
}
async fn sync(
    store: &ClientStore,
    person: &Person,
    authority: &FixedDemoAuthority,
    peers: &[Peer],
    ms: u64,
) -> SyncReport {
    SyncClient {
        store,
        identity: &person.age,
        credential: person.credential.id(),
        authority,
        peers,
    }
    .once(time(ms))
    .await
    .unwrap()
}
fn encrypted(person: &Person, authority: &FixedDemoAuthority, n: u8) -> (SignedRecord, Vec<u8>) {
    let mut chat: ChatMessage = message(person, authority).chat().unwrap();
    chat.nonce = format!("{n:032x}");
    let record = chat.sign(&person.key).unwrap();
    let bytes = crypto::seal_chat(
        &record,
        &authority.credentials.values().cloned().collect::<Vec<_>>(),
    )
    .unwrap();
    (record, bytes)
}
async fn enqueue(
    store: &ClientStore,
    record: &SignedRecord,
    bytes: &[u8],
    targets: Vec<DeliveryTarget>,
) {
    let chat = record.chat().unwrap();
    store
        .commit_local_record_with_outbox(
            PreparedLocalRecord::new(
                record.id(),
                bytes.to_vec(),
                RecordMetadata::new(
                    "chat.message",
                    Some(chat.space_id),
                    Some(chat.stream_id),
                    Some(chat.config_id),
                )
                .unwrap(),
                targets,
                time(1),
            )
            .unwrap(),
        )
        .await
        .unwrap();
}
const RESET: &str = "BEGIN IMMEDIATE; DELETE FROM deliveries; DELETE FROM objects; DELETE FROM sqlite_sequence WHERE name='deliveries'; UPDATE node_meta SET value=lower(hex(randomblob(32))) WHERE key='storage_generation'; COMMIT;";

#[tokio::test]
async fn reset_restores_stored_bytes_after_quota_failure_and_client_restart() {
    let alice = person(21);
    let authority = authority(&[&alice]);
    let (record, bytes) = encrypted(&alice, &authority, 1);
    let a = Node::new().await;
    let b = Node::new().await;
    let pin = a.store.peer_id();
    let dir = tempfile::tempdir().unwrap();
    let store = ClientStore::open(dir.path()).await.unwrap();
    enqueue(&store, &record, &bytes, vec![a.target(), b.target()]).await;
    assert_eq!(
        sync(
            &store,
            &alice,
            &authority,
            &[a.peer(true, true), b.peer(true, true)],
            100
        )
        .await
        .stored,
        2
    );
    sync(
        &store,
        &alice,
        &authority,
        &[a.peer(true, true), b.peer(true, true)],
        200,
    )
    .await;
    let a = a
        .mutate(&format!("{RESET} UPDATE mailboxes SET quota_bytes=1;"))
        .await;
    assert_eq!(a.store.peer_id(), pin);
    let report = sync(
        &store,
        &alice,
        &authority,
        &[a.peer(true, true), b.peer(true, true)],
        300,
    )
    .await;
    assert_eq!(
        (
            report.generation_changes,
            report.repaired,
            report.repair_pending,
            report.retry
        ),
        (1, 0, 1, 1)
    );
    assert_eq!(store.stats().await.unwrap().stored, 2); // Historical ACKs survive.
    assert_eq!(
        store
            .display_sources(authority.space, authority.stream)
            .await
            .unwrap()[0]
            .status,
        "REPAIR_PENDING"
    );
    store.close().await.unwrap();
    let store = ClientStore::open(dir.path()).await.unwrap();
    let a = a.mutate("UPDATE mailboxes SET quota_bytes=16777216").await;
    let peers = [a.peer(true, true), b.peer(true, true)];
    assert_eq!(
        sync(&store, &alice, &authority, &peers, 300).await.repaired,
        0
    ); // Durable backoff.
    let report = sync(&store, &alice, &authority, &peers, 100_000).await;
    assert_eq!((report.repaired, report.repair_pending), (1, 0));
    assert!(a.contains(&bytes).await);
    assert_eq!(a.inventory().await.entries.len(), 1);
    let report = sync(&store, &alice, &authority, &peers, 200_000).await;
    assert_eq!((report.repaired, report.downloaded), (0, 0));
    assert_eq!(store.stats().await.unwrap().records, 1);
    assert_eq!(store.stats().await.unwrap().sources, 1);
    store.close().await.unwrap();
    a.stop().await;
    b.stop().await;
}

#[tokio::test]
async fn surviving_peer_supplies_exact_eager_bytes_but_lazy_stays_on_demand() {
    let alice = person(21);
    let authority = authority(&[&alice]);
    let (_, bytes) = encrypted(&alice, &authority, 1);
    let lazy = b"PUBLIC LAZY TRANSFER FIXTURE";
    let a = Node::new().await;
    let b = Node::new().await;
    for node in [&a, &b] {
        node.post(&bytes, TransferHint::Eager).await;
        node.post(lazy, TransferHint::Lazy).await;
    }
    let dir = tempfile::tempdir().unwrap();
    let store = ClientStore::open(dir.path()).await.unwrap();
    // Persist inventory knowledge without a usable local copy (failed eager GET
    // and deliberately deferred lazy body). Neither entry authorizes a message.
    for node in [&a, &b] {
        let page = node.inventory().await;
        for entry in page.entries {
            store
                .stage_inbox(
                    node.store.peer_id(),
                    node.mailbox.mailbox_id,
                    page.storage_generation.clone(),
                    entry,
                    None,
                    time(1),
                )
                .await
                .unwrap();
        }
    }
    assert_eq!(store.stats().await.unwrap().objects, 0);
    let a = a.mutate(RESET).await;
    let report = sync(
        &store,
        &alice,
        &authority,
        &[a.peer(true, true), b.peer(true, false)],
        100,
    )
    .await;
    assert_eq!(
        (
            report.repair_downloaded,
            report.repaired,
            report.repair_deferred,
            report.repair_pending
        ),
        (1, 1, 1, 1)
    );
    assert_eq!(report.downloaded, 0);
    assert!(a.contains(&bytes).await);
    assert!(!a.contains(lazy).await);
    assert!(b.contains(lazy).await);
    assert!(
        store
            .get_object(ObjectId::of_ciphertext(lazy))
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(store.stats().await.unwrap().records, 0); // Repair is not admission.
    // A user-authorized file fetch may subsequently populate the local cache.
    let page = b.inventory().await;
    let lazy_entry = page
        .entries
        .into_iter()
        .find(|e| e.transfer_hint == TransferHint::Lazy)
        .unwrap();
    store
        .stage_inbox(
            b.store.peer_id(),
            b.mailbox.mailbox_id,
            page.storage_generation,
            lazy_entry,
            Some(lazy.to_vec()),
            time(200),
        )
        .await
        .unwrap();
    let report = sync(
        &store,
        &alice,
        &authority,
        &[a.peer(true, true), b.peer(true, false)],
        100_000,
    )
    .await;
    assert_eq!((report.repaired, report.repair_pending), (1, 0));
    assert!(a.contains(lazy).await);
    assert_eq!(
        a.inventory()
            .await
            .entries
            .iter()
            .filter(|e| e.transfer_hint == TransferHint::Lazy)
            .count(),
        1
    );
    store.close().await.unwrap();
    a.stop().await;
    b.stop().await;
}

#[tokio::test]
async fn reused_sequence_after_rollback_keeps_pending_work_and_detects_equal_head() {
    for equal_head in [false, true] {
        let alice = person(21);
        let authority = authority(&[&alice]);
        let a = Node::new().await;
        let dir = tempfile::tempdir().unwrap();
        let store = ClientStore::open(dir.path()).await.unwrap();
        let mut originals = Vec::new();
        for n in 1..=3 {
            let (_, bytes) = encrypted(&alice, &authority, n);
            a.post(&bytes, TransferHint::Eager).await;
            originals.push(bytes);
        }
        let page = a.inventory().await;
        let generation = page.storage_generation.clone();
        for (entry, bytes) in page.entries.into_iter().zip(&originals) {
            store
                .stage_inbox(
                    a.store.peer_id(),
                    a.mailbox.mailbox_id,
                    generation.clone(),
                    entry,
                    Some(bytes.clone()),
                    time(1),
                )
                .await
                .unwrap();
        }
        let a=a.mutate("DELETE FROM deliveries; DELETE FROM objects; DELETE FROM sqlite_sequence WHERE name='deliveries';").await;
        let total = if equal_head { 3 } else { 1 };
        for n in 10..10 + total {
            let (_, bytes) = encrypted(&alice, &authority, n);
            a.post(&bytes, TransferHint::Eager).await;
        }
        let report = sync(&store, &alice, &authority, &[a.peer(true, true)], 100).await;
        assert_eq!(report.generation_changes, 1);
        assert_eq!(report.repaired, 3);
        assert_eq!(report.accepted, 3 + total as u64);
        assert_eq!(store.stats().await.unwrap().records, 3 + total as u64);
        assert!(store.pending_inbox(128).await.unwrap().is_empty());
        assert_eq!(a.inventory().await.storage_generation, generation);
        for bytes in &originals {
            assert!(a.contains(bytes).await);
        }
        sync(&store, &alice, &authority, &[a.peer(true, true)], 200).await;
        assert_eq!(store.stats().await.unwrap().records, 3 + total as u64);
        store.close().await.unwrap();
        a.stop().await;
    }
}

#[tokio::test]
async fn full_id_comparison_and_repair_are_bounded_and_resume_across_restart() {
    let alice = person(21);
    let authority = authority(&[&alice]);
    let a = Node::new().await;
    for n in 0..260 {
        a.post(
            format!("PUBLIC TRANSPORT FIXTURE {n}").as_bytes(),
            TransferHint::Eager,
        )
        .await;
    }
    let dir = tempfile::tempdir().unwrap();
    let store = ClientStore::open(dir.path()).await.unwrap();
    for expected in [0, 0, 1] {
        assert_eq!(
            sync(&store, &alice, &authority, &[a.peer(true, true)], 100)
                .await
                .inventory_scans,
            expected
        );
    }
    assert_eq!(store.stats().await.unwrap().objects, 260);
    let a=a.mutate("DELETE FROM deliveries WHERE arrival_seq=17; DELETE FROM objects WHERE object_id NOT IN (SELECT object_id FROM deliveries);").await;
    let report = sync(&store, &alice, &authority, &[a.peer(true, true)], 200).await;
    assert_eq!(
        (
            report.generation_changes,
            report.inventory_scans,
            report.repaired
        ),
        (0, 0, 0)
    );
    store.close().await.unwrap();
    let store = ClientStore::open(dir.path()).await.unwrap();
    assert_eq!(
        sync(&store, &alice, &authority, &[a.peer(true, true)], 200)
            .await
            .inventory_scans,
        0
    );
    let report = sync(&store, &alice, &authority, &[a.peer(true, true)], 200).await;
    assert_eq!(
        (
            report.inventory_scans,
            report.repaired,
            report.repair_pending
        ),
        (1, 1, 0)
    );
    assert!(a.contains(b"PUBLIC TRANSPORT FIXTURE 16").await);
    // Total reset needs three bounded repair batches, preserving all 260 IDs.
    let a = a.mutate(RESET).await;
    let report = sync(&store, &alice, &authority, &[a.peer(true, true)], 100_000).await;
    assert_eq!((report.repaired, report.repair_pending), (128, 132));
    store.close().await.unwrap();
    let store = ClientStore::open(dir.path()).await.unwrap();
    let report = sync(&store, &alice, &authority, &[a.peer(true, true)], 200_000).await;
    assert_eq!((report.repaired, report.repair_pending), (128, 4));
    let report = sync(&store, &alice, &authority, &[a.peer(true, true)], 300_000).await;
    assert_eq!((report.repaired, report.repair_pending), (4, 0));
    let raw = Connection::open(a.dir.path().join("replica.sqlite")).unwrap();
    assert_eq!(
        raw.query_row::<i64, _, _>("SELECT count(*) FROM deliveries", [], |r| r.get(0))
            .unwrap(),
        260
    );
    assert_eq!(store.stats().await.unwrap().objects, 260);
    store.close().await.unwrap();
    a.stop().await;
}

#[tokio::test]
async fn repair_cannot_release_held_messages_or_copy_to_an_unrelated_mailbox() {
    let alice = person(21);
    let mut authority = authority(&[&alice]);
    let (sent, bytes) = encrypted(&alice, &authority, 1);
    let (unsent, pending) = encrypted(&alice, &authority, 2);
    let a = Node::new().await;
    let other = Node::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = ClientStore::open(dir.path()).await.unwrap();
    enqueue(&store, &sent, &bytes, vec![a.target()]).await;
    sync(&store, &alice, &authority, &[a.peer(true, true)], 100).await;
    enqueue(&store, &unsent, &pending, vec![a.target()]).await;
    authority.config = elo_core::ids::RecordId::from_bytes([77; 32]);
    let a = a.mutate(RESET).await;
    let report = sync(
        &store,
        &alice,
        &authority,
        &[a.peer(true, true), other.peer(true, true)],
        200,
    )
    .await;
    assert_eq!((report.held, report.repaired), (1, 1));
    assert_eq!(store.stats().await.unwrap().held, 1);
    assert!(a.contains(&bytes).await);
    assert!(!a.contains(&pending).await);
    assert!(other.inventory().await.entries.is_empty());
    assert_eq!(store.stats().await.unwrap().records, 2);
    store.close().await.unwrap();
    a.stop().await;
    other.stop().await;
}

#[tokio::test]
async fn read_only_detection_does_not_write_and_new_peer_key_is_a_distinct_target() {
    let alice = person(21);
    let authority = authority(&[&alice]);
    let (_, bytes) = encrypted(&alice, &authority, 1);
    let a = Node::new().await;
    a.post(&bytes, TransferHint::Eager).await;
    let dir = tempfile::tempdir().unwrap();
    let store = ClientStore::open(dir.path()).await.unwrap();
    sync(&store, &alice, &authority, &[a.peer(true, false)], 100).await;
    let a = a.mutate(RESET).await;
    let report = sync(&store, &alice, &authority, &[a.peer(true, false)], 200).await;
    assert_eq!((report.repair_pending, report.repaired), (1, 0));
    assert!(!a.contains(&bytes).await);
    let a = a
        .mutate("DELETE FROM node_meta WHERE key='signing_seed'")
        .await;
    let report = sync(&store, &alice, &authority, &[a.peer(true, true)], 100_000).await;
    assert_eq!((report.repair_pending, report.repaired), (1, 0));
    assert!(!a.contains(&bytes).await);
    store.close().await.unwrap();
    a.stop().await;
}

#[tokio::test]
async fn migration_from_v3_preserves_queued_bytes_receipts_and_authority_snapshots() {
    let dir = tempfile::tempdir().unwrap();
    let raw = Connection::open(dir.path().join("client.sqlite")).unwrap();
    for migration in [
        include_str!("../../../migrations/001_client.sql"),
        include_str!("../../../migrations/002_client_inbox.sql"),
        include_str!("../../../migrations/003_client_authority.sql"),
    ] {
        raw.execute_batch(migration).unwrap();
    }
    let object = ObjectId::of_ciphertext(b"PUBLIC MIGRATION FIXTURE");
    let id = "02".repeat(32);
    let space = "03".repeat(32);
    let stream = "04".repeat(16);
    let peer = "05".repeat(32);
    let mailbox = "06".repeat(32);
    let generation = "07".repeat(32);
    raw.execute(
        "INSERT INTO objects VALUES(?1,?2,?3,1)",
        params![
            object.to_string(),
            b"PUBLIC MIGRATION FIXTURE".as_slice(),
            b"PUBLIC MIGRATION FIXTURE".len() as i64
        ],
    )
    .unwrap();
    raw.execute(
        "INSERT INTO records VALUES(?1,'stream.config',?2,?3,?1,'LOCAL',1)",
        params![id, space, stream],
    )
    .unwrap();
    raw.execute(
        "INSERT INTO record_sources VALUES(?1,?2,-1)",
        params![id, object.to_string()],
    )
    .unwrap();
    raw.execute(
        "INSERT INTO outbox VALUES(?1,?2,?3,?4,'STORED',1,0,NULL,?5)",
        params![
            id,
            object.to_string(),
            peer,
            mailbox,
            b"PRESERVED RECEIPT".as_slice()
        ],
    )
    .unwrap();
    raw.execute(
        "INSERT INTO stream_heads VALUES(?1,?2,?3,1,'KNOWN')",
        params![space, stream, id],
    )
    .unwrap();
    raw.execute(
        "INSERT INTO authority_snapshots VALUES(?1,?2,?3)",
        params![space, stream, b"OPAQUE SNAPSHOT".as_slice()],
    )
    .unwrap();
    raw.execute(
        "INSERT INTO peer_cursors VALUES(?1,?2,?3,1)",
        params![peer, mailbox, generation],
    )
    .unwrap();
    raw.execute(
        "INSERT INTO inbox VALUES(?1,?2,?3,1,?4,'eager','PENDING')",
        params![peer, mailbox, generation, object.to_string()],
    )
    .unwrap();
    drop(raw);
    let store = ClientStore::open(dir.path()).await.unwrap();
    assert_eq!(
        store.get_object(object).await.unwrap().unwrap(),
        b"PUBLIC MIGRATION FIXTURE"
    );
    assert_eq!(
        store
            .authority_snapshot(space.parse().unwrap(), stream.parse().unwrap())
            .await
            .unwrap()
            .unwrap(),
        b"OPAQUE SNAPSHOT"
    );
    assert_eq!(store.pending_inbox(128).await.unwrap().len(), 1);
    assert_eq!(store.stats().await.unwrap().stored, 1);
    store.close().await.unwrap();
    let raw = Connection::open(dir.path().join("client.sqlite")).unwrap();
    assert_eq!(
        raw.query_row::<Vec<u8>, _, _>("SELECT receipt_record FROM replica_copies", [], |r| r
            .get(0))
            .unwrap(),
        b"PRESERVED RECEIPT"
    );
    assert_eq!(
        raw.pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
            .unwrap(),
        6
    );
}
