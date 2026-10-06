use elo_core::{
    erasure::{self, RetentionClaim},
    ids::{ObjectId, RecordId},
    message_retention::MessageRetention,
    replica::{
        ChildMailbox, MailboxDescriptor, ReplicaError, ReplicaStore, TransferHint, VerifiedReceipt,
    },
    retention_access::{Context, Operation, Proof, public_key},
    vault::Session,
};
use rusqlite::{Connection, params};

const REQUEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const ACCEPT: &str = "2222222222222222222222222222222222222222222222222222222222222222";
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
struct Fixture {
    dir: tempfile::TempDir,
    store: ReplicaStore,
    mailbox: MailboxDescriptor,
    alice: Session,
    bob: Session,
    record: RecordId,
    body: Vec<u8>,
    locator: Vec<u8>,
}
impl Fixture {
    async fn new(policy: MessageRetention, allowed: Vec<MessageRetention>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = ReplicaStore::open(dir.path())
            .await
            .unwrap()
            .with_allowed_message_retentions(allowed)
            .unwrap();
        let mailbox = store.create_mailbox(100_000).await.unwrap();
        let alice = Session::create().unwrap().0;
        let bob = Session::create().unwrap().0;
        store
            .set_space_members(
                mailbox.mailbox_id,
                vec![alice.identity_id(), bob.identity_id()],
            )
            .await
            .unwrap();
        let record = RecordId::from_bytes([91; 32]);
        let wrap = |bytes: Vec<u8>, retention| {
            erasure::wrap_subjects_with_retention(
                bytes,
                alice.credential(),
                alice.signing_key(),
                vec![alice.identity_id(), bob.identity_id()],
                Some(retention),
            )
            .unwrap()
        };
        let body = wrap(
            b"synthetic encrypted body".to_vec(),
            RetentionClaim::MessageBody {
                locator_nonce: "12".repeat(16),
                record_id: record,
                lifetime_seconds: policy,
                direct_peer: Some(bob.identity_id()),
                request_key: public_key(REQUEST).unwrap(),
                accept_key: Some(public_key(ACCEPT).unwrap()),
            },
        );
        let locator = wrap(
            b"synthetic encrypted locator".to_vec(),
            RetentionClaim::MessageLocator {
                locator_nonce: "12".repeat(16),
                body_object_id: ObjectId::of_ciphertext(&body),
                record_id: record,
                lifetime_seconds: policy,
                request_key: public_key(REQUEST).unwrap(),
            },
        );
        Self {
            dir,
            store,
            mailbox,
            alice,
            bob,
            record,
            body,
            locator,
        }
    }
    fn db(&self) -> Connection {
        Connection::open(self.dir.path().join("replica.sqlite")).unwrap()
    }
    async fn post(
        &self,
        mailbox: &MailboxDescriptor,
        bytes: &[u8],
    ) -> Result<(bool, Vec<u8>), ReplicaError> {
        self.store
            .post_authenticated(
                mailbox.mailbox_id,
                mailbox.write_token.clone(),
                ObjectId::of_ciphertext(bytes),
                bytes.to_vec(),
                TransferHint::Eager,
                true,
                Some(self.alice.credential().into()),
            )
            .await
    }
    async fn upload(&self) {
        for bytes in [&self.locator, &self.body] {
            let (_, receipt) = self.post(&self.mailbox, bytes).await.unwrap();
            VerifiedReceipt::verify(
                &receipt,
                self.store.key(),
                self.mailbox.mailbox_id,
                ObjectId::of_ciphertext(bytes),
                bytes.len(),
            )
            .unwrap();
        }
    }
    async fn get(&self, bytes: &[u8]) -> Result<Vec<u8>, ReplicaError> {
        self.store
            .get(
                self.mailbox.mailbox_id,
                self.mailbox.read_token.clone(),
                ObjectId::of_ciphertext(bytes),
            )
            .await
    }
    fn proof(&self, operation: Operation, session: &Session) -> Proof {
        Proof::issue(
            if matches!(operation, Operation::Accept) {
                ACCEPT
            } else {
                REQUEST
            },
            &Context {
                operation,
                replica: self.store.peer_id(),
                mailbox: self.mailbox.mailbox_id,
                object: ObjectId::of_ciphertext(&self.body),
                record: self.record,
                actor: session.credential().into(),
            },
            now(),
        )
        .unwrap()
    }
}

#[tokio::test]
async fn no_expiry_retains_body_locator_metadata_and_authenticated_dm_after_acceptance() {
    let f = Fixture::new(MessageRetention::NoExpiry, vec![MessageRetention::NoExpiry]).await;
    f.upload().await;
    let body_id = ObjectId::of_ciphertext(&f.body);
    assert!(matches!(
        f.store
            .accept_message(
                f.mailbox.mailbox_id,
                f.alice.credential().into(),
                body_id,
                f.record,
                f.proof(Operation::Accept, &f.alice)
            )
            .await,
        Err(ReplicaError::Unauthorized)
    ));
    f.store
        .accept_message(
            f.mailbox.mailbox_id,
            f.bob.credential().into(),
            body_id,
            f.record,
            f.proof(Operation::Accept, &f.bob),
        )
        .await
        .unwrap();
    // Move receipt times farther back than the old 30-day locator lifetime.
    for table in ["message_bodies", "message_locators"] {
        f.db()
            .execute(
                &format!("UPDATE {table} SET received_local_ms=?1"),
                [now() as i64 - 40 * 86_400_000],
            )
            .unwrap();
    }
    f.store.maintain_message_lifetime().await.unwrap();
    assert_eq!(f.get(&f.body).await.unwrap(), f.body);
    assert_eq!(f.get(&f.locator).await.unwrap(), f.locator);
    for table in ["message_bodies", "message_locators"] {
        let row: (String, Option<i64>) = f
            .db()
            .query_row(
                &format!("SELECT retention_policy,expires_local_ms FROM {table}"),
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(row, ("no_expiry".into(), None));
    }
    assert!(!f.post(&f.mailbox, &f.body).await.unwrap().0);
    let usage = f
        .store
        .space_storage(f.mailbox.mailbox_id, now())
        .await
        .unwrap();
    assert!(usage.used_bytes >= (f.body.len() + f.locator.len() + 2048) as u64);
}

#[tokio::test]
async fn finite_48h_duplicates_including_child_mailbox_never_extend_deadlines() {
    let f = Fixture::new(MessageRetention::Hours48, vec![MessageRetention::Hours48]).await;
    f.upload().await;
    let row = |table| {
        f.db()
            .query_row(
                &format!("SELECT received_local_ms,expires_local_ms FROM {table}"),
                [],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
            )
            .unwrap()
    };
    let body = row("message_bodies");
    let locator = row("message_locators");
    assert_eq!(body.1 - body.0, 172_800_000);
    assert_eq!(locator.1 - locator.0, 30 * 86_400_000);
    let child = MailboxDescriptor::random().unwrap();
    f.store
        .create_child(
            f.mailbox.mailbox_id,
            f.mailbox.write_token.clone(),
            ChildMailbox {
                descriptor: child.clone(),
                quota_bytes: 50_000,
                expires_at: now() + 86_400_000,
            },
        )
        .await
        .unwrap();
    for mailbox in [&f.mailbox, &child] {
        for bytes in [&f.locator, &f.body] {
            f.post(mailbox, bytes).await.unwrap();
        }
    }
    assert_eq!(row("message_bodies"), body);
    assert_eq!(row("message_locators"), locator);
    f.db()
        .execute(
            "UPDATE message_bodies SET expires_local_ms=received_local_ms",
            [],
        )
        .unwrap();
    f.store.maintain_message_lifetime().await.unwrap();
    assert!(matches!(f.get(&f.body).await, Err(ReplicaError::NotFound)));
    assert!(matches!(
        f.store
            .get(
                child.mailbox_id,
                child.read_token,
                ObjectId::of_ciphertext(&f.body)
            )
            .await,
        Err(ReplicaError::NotFound)
    ));
    assert_eq!(f.get(&f.locator).await.unwrap(), f.locator);
}

#[tokio::test]
async fn public_policy_rejects_48h_and_no_expiry_even_for_signed_uploads() {
    for policy in [MessageRetention::Hours48, MessageRetention::NoExpiry] {
        let f = Fixture::new(policy, MessageRetention::public_policies()).await;
        for bytes in [&f.locator, &f.body] {
            assert!(matches!(
                f.post(&f.mailbox, bytes).await,
                Err(ReplicaError::Invalid)
            ));
        }
        assert_eq!(
            f.db()
                .query_row("SELECT count(*) FROM objects", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
}

#[tokio::test]
async fn host_policy_also_rejects_refill_after_configuration_is_narrowed() {
    let mut f = Fixture::new(MessageRetention::Hours48, vec![MessageRetention::Hours48]).await;
    f.upload().await;
    f.db()
        .execute(
            "UPDATE message_bodies SET expires_local_ms=received_local_ms",
            [],
        )
        .unwrap();
    f.store.maintain_message_lifetime().await.unwrap();
    f.store
        .request_message(
            f.mailbox.mailbox_id,
            f.bob.credential().into(),
            ObjectId::of_ciphertext(&f.body),
            f.record,
            f.proof(Operation::Request, &f.bob),
        )
        .await
        .unwrap();
    f.store = f
        .store
        .with_allowed_message_retentions(MessageRetention::public_policies())
        .unwrap();
    assert!(matches!(
        f.post(&f.mailbox, &f.body).await,
        Err(ReplicaError::Invalid)
    ));
}

#[tokio::test]
async fn no_expiry_does_not_bypass_quota_or_pruned_tombstones() {
    let f = Fixture::new(MessageRetention::NoExpiry, vec![MessageRetention::NoExpiry]).await;
    f.post(&f.mailbox, &f.locator).await.unwrap();
    f.db()
        .execute(
            "UPDATE mailboxes SET quota_bytes=?1",
            [(f.locator.len() + 1024) as i64],
        )
        .unwrap();
    assert!(matches!(
        f.post(&f.mailbox, &f.body).await,
        Err(ReplicaError::Quota)
    ));
    f.db()
        .execute("UPDATE mailboxes SET quota_bytes=100000", [])
        .unwrap();
    f.db()
        .execute(
            "INSERT INTO pruned_objects VALUES(?1,?2,?3)",
            params![
                f.mailbox.mailbox_id.to_string(),
                ObjectId::of_ciphertext(&f.body).to_string(),
                now() as i64
            ],
        )
        .unwrap();
    assert!(matches!(
        f.post(&f.mailbox, &f.body).await,
        Err(ReplicaError::Pruned(_))
    ));
}

#[tokio::test]
async fn v9_migration_preserves_fixed_deadlines_and_access_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let db = Connection::open(dir.path().join("replica.sqlite")).unwrap();
    for sql in [
        include_str!("../../../migrations/001_replica.sql"),
        include_str!("../../../migrations/002_replica_mailbox_delegation.sql"),
        include_str!("../../../migrations/003_replica_space_access.sql"),
        include_str!("../../../migrations/004_replica_retention.sql"),
        include_str!("../../../migrations/005_replica_account_erasure.sql"),
        include_str!("../../../migrations/006_replica_packing.sql"),
        include_str!("../../../migrations/007_replica_message_lifetime.sql"),
        include_str!("../../../migrations/008_replica_request_nonces.sql"),
        include_str!("../../../migrations/009_replica_message_access.sql"),
    ] {
        db.execute_batch(sql).unwrap();
    }
    let root = "01".repeat(32);
    let object = "02".repeat(32);
    let record = "03".repeat(32);
    let actor = "04".repeat(32);
    db.execute(
        "INSERT INTO mailboxes VALUES(?1,?2,?3,100000)",
        params![root, vec![1u8; 32], vec![2u8; 32]],
    )
    .unwrap();
    db.execute("INSERT INTO message_bodies VALUES(?1,?2,?3,?4,?5,NULL,21600,1000,21601000,NULL,NULL,?6,NULL)", params![root,object,record,"12".repeat(16),actor,public_key(REQUEST).unwrap()]).unwrap();
    db.execute(
        "INSERT INTO message_locators VALUES(?1,?2,?3,?4,?5,21600,1000,2592001000,?6)",
        params![
            root,
            "05".repeat(32),
            object,
            record,
            "12".repeat(16),
            public_key(REQUEST).unwrap()
        ],
    )
    .unwrap();
    db.execute(
        "INSERT INTO message_requests VALUES(?1,?2,?3,?4,1000,301000,NULL,NULL,NULL)",
        params![root, object, record, actor],
    )
    .unwrap();
    drop(db);
    let replica = ReplicaStore::open(dir.path()).await.unwrap();
    let db = Connection::open(dir.path().join("replica.sqlite")).unwrap();
    let row: (String, i64, i64, String) = db.query_row("SELECT retention_policy,received_local_ms,expires_local_ms,request_key FROM message_bodies", [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).unwrap();
    assert_eq!(
        row,
        ("6h".into(), 1000, 21601000, public_key(REQUEST).unwrap())
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM message_requests", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |r| r
            .get::<_, i64>(
            0
        ))
        .unwrap(),
        0
    );
    assert_eq!(
        db.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
            .unwrap(),
        10
    );
    drop(db);
    drop(replica);
    ReplicaStore::open(dir.path()).await.unwrap();
}
