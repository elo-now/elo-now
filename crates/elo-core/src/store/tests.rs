use super::*;
use crate::ids::{MailboxId, PeerId, SpaceId, StreamId};
use std::process::Command as ProcessCommand;
use tempfile::TempDir;

pub(super) fn time(value: u64) -> LocalTime {
    LocalTime::from_millis(value).unwrap()
}

pub(super) fn fixture(seed: u8, target_count: usize) -> PreparedLocalRecord {
    PreparedLocalRecord::new(
        RecordId::of_record_bytes(&[seed]),
        vec![seed; 80], // OPAQUE TEST BYTES, not encryption.
        RecordMetadata::new(
            "dev.storage_fixture",
            Some(SpaceId::from_bytes([1; 32])),
            Some(StreamId::from_bytes([2; 16])),
            Some(RecordId::from_bytes([3; 32])),
        )
        .unwrap(),
        (0..target_count)
            .map(|i| DeliveryTarget {
                peer_id: PeerId::from_bytes([i as u8; 32]),
                mailbox_id: MailboxId::from_bytes([7; 32]),
            })
            .collect(),
        time(100),
    )
    .unwrap()
}

#[test]
fn input_limits_are_checked_before_enqueue() {
    assert!(LocalTime::from_millis(u64::MAX).is_err());
    assert!(RecordMetadata::new("", None, None, None).is_err());
    assert!(RecordMetadata::new("Bad\nKind", None, None, None).is_err());
    let base = fixture(1, 1);
    let make = |bytes, targets| {
        PreparedLocalRecord::new(
            base.record_id,
            bytes,
            base.metadata.clone(),
            targets,
            time(1),
        )
    };
    assert!(make(vec![], vec![]).is_err());
    assert!(make(vec![0; MAX_OBJECT_BYTES + 1], vec![]).is_err());
    assert!(make(vec![0], vec![base.targets[0]; 2]).is_err());
    assert!(make(vec![0], vec![base.targets[0]; MAX_INITIAL_TARGETS + 1]).is_err());
    assert!(make(vec![0], vec![]).is_ok());
}

#[tokio::test]
async fn correct_pragmas_and_migration() {
    let directory = TempDir::new().unwrap();
    let store = ClientStore::open(directory.path()).await.unwrap();
    store
        .call(|connection| {
            verify_pragmas(connection)?;
            validate_schema(connection)?;
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(store.stats().await.unwrap().objects, 0);
    store.close().await.unwrap();
}

#[tokio::test]
async fn commit_survives_close_and_reopen() {
    let directory = TempDir::new().unwrap();
    let input = fixture(1, 2);
    let store = ClientStore::open(directory.path()).await.unwrap();
    let result = store
        .commit_local_record_with_outbox(input.clone())
        .await
        .unwrap();
    assert_eq!(result.disposition, CommitDisposition::Inserted);
    assert_eq!(result.target_count, 2);
    store.close().await.unwrap();
    let reopened = ClientStore::open(directory.path()).await.unwrap();
    let stats = reopened.stats().await.unwrap();
    assert_eq!(
        (stats.objects, stats.records, stats.sources, stats.pending),
        (1, 1, 1, 2)
    );
    assert_eq!(
        reopened.get_object(input.object_id).await.unwrap(),
        Some(input.ciphertext)
    );
    reopened.close().await.unwrap();
}

#[tokio::test]
async fn five_identical_retries_are_noops_even_after_claim() {
    let directory = TempDir::new().unwrap();
    let store = ClientStore::open(directory.path()).await.unwrap();
    let input = fixture(2, 2);
    store
        .commit_local_record_with_outbox(input.clone())
        .await
        .unwrap();
    store.claim_next(time(100)).await.unwrap().unwrap();
    let before = store.stats().await.unwrap();
    for _ in 0..5 {
        let mut retry = input.clone();
        retry.created = time(999); // local time does not rewrite first_seen.
        retry.targets.reverse(); // Constructor normally sorts; compare normalized input below.
        retry.targets.sort_unstable();
        assert_eq!(
            store
                .commit_local_record_with_outbox(retry)
                .await
                .unwrap()
                .disposition,
            CommitDisposition::AlreadyPresent
        );
    }
    assert_eq!(store.stats().await.unwrap(), before);
    let first_seen: i64 = store
        .call(move |c| {
            Ok(c.query_row(
                "SELECT first_seen_local_ms FROM records WHERE record_id=?1",
                [input.record_id.to_string()],
                |r| r.get(0),
            )?)
        })
        .await
        .unwrap();
    assert_eq!(first_seen, 100);
    store.close().await.unwrap();
}

#[tokio::test]
async fn changed_targets_metadata_or_ciphertext_cannot_replace_a_commit() {
    let directory = TempDir::new().unwrap();
    let store = ClientStore::open(directory.path()).await.unwrap();
    let input = fixture(3, 2);
    store
        .commit_local_record_with_outbox(input.clone())
        .await
        .unwrap();
    let before = store.stats().await.unwrap();
    let mut targets = input.clone();
    targets.targets.pop();
    assert!(matches!(
        store.commit_local_record_with_outbox(targets).await,
        Err(StoreError::IdempotencyConflict(_))
    ));
    let mut metadata = input.clone();
    metadata.metadata = RecordMetadata::new("other.kind", None, None, None).unwrap();
    assert!(matches!(
        store.commit_local_record_with_outbox(metadata).await,
        Err(StoreError::IdempotencyConflict(_))
    ));
    let replacement = PreparedLocalRecord::new(
        input.record_id,
        vec![99; 80],
        input.metadata.clone(),
        input.targets.clone(),
        time(100),
    )
    .unwrap();
    assert!(matches!(
        store.commit_local_record_with_outbox(replacement).await,
        Err(StoreError::IdempotencyConflict(_))
    ));
    assert_eq!(store.stats().await.unwrap(), before);
    store.close().await.unwrap();
}

#[tokio::test]
async fn failure_on_second_target_rolls_back_every_new_row() {
    let directory = TempDir::new().unwrap();
    let store = ClientStore::open(directory.path()).await.unwrap();
    store
        .call(|c| {
            c.execute_batch(
                "CREATE TEMP TRIGGER fail_second BEFORE INSERT ON main.outbox
            WHEN (SELECT count(*) FROM outbox)=1 BEGIN SELECT RAISE(ABORT,'test failure'); END;",
            )?;
            Ok(())
        })
        .await
        .unwrap();
    assert!(
        store
            .commit_local_record_with_outbox(fixture(4, 2))
            .await
            .is_err()
    );
    let stats = store.stats().await.unwrap();
    assert_eq!(
        (stats.objects, stats.records, stats.sources, stats.pending),
        (0, 0, 0, 0)
    );
    store
        .call(|c| {
            c.execute_batch("DROP TRIGGER temp.fail_second")?;
            Ok(())
        })
        .await
        .unwrap();
    store
        .commit_local_record_with_outbox(fixture(4, 2))
        .await
        .unwrap();
    store.close().await.unwrap();
}

#[tokio::test]
async fn one_object_cannot_be_relabelled_as_a_second_record() {
    let directory = TempDir::new().unwrap();
    let store = ClientStore::open(directory.path()).await.unwrap();
    let input = fixture(5, 2);
    store
        .commit_local_record_with_outbox(input.clone())
        .await
        .unwrap();
    let before = store.stats().await.unwrap();
    let mut second = input;
    second.record_id = RecordId::from_bytes([44; 32]);
    assert!(store.commit_local_record_with_outbox(second).await.is_err());
    assert_eq!(store.stats().await.unwrap(), before);
    store.close().await.unwrap();
}

#[tokio::test]
async fn disk_full_returns_error_and_rolls_back() {
    let directory = TempDir::new().unwrap();
    let store = ClientStore::open(directory.path()).await.unwrap();
    store
        .call(|c| {
            let pages: i64 = c.pragma_query_value(None, "page_count", |r| r.get(0))?;
            let _: i64 =
                c.query_row(&format!("PRAGMA max_page_count={pages}"), [], |r| r.get(0))?;
            Ok(())
        })
        .await
        .unwrap();
    let base = fixture(6, 2);
    let input = PreparedLocalRecord::new(
        base.record_id,
        vec![0xaa; 2 * 1024 * 1024],
        base.metadata,
        base.targets,
        time(100),
    )
    .unwrap();
    let error = store
        .commit_local_record_with_outbox(input)
        .await
        .unwrap_err();
    assert!(
        matches!(error, StoreError::Sqlite(rusqlite::Error::SqliteFailure(code, _))
        if code.code == rusqlite::ErrorCode::DiskFull)
    );
    let stats = store.stats().await.unwrap();
    assert_eq!(
        (stats.objects, stats.records, stats.sources, stats.pending),
        (0, 0, 0, 0)
    );
    store.close().await.unwrap();
}

#[tokio::test]
async fn busy_writer_does_not_report_local_success() {
    let directory = TempDir::new().unwrap();
    let store = ClientStore::open(directory.path()).await.unwrap();
    // A deliberately non-cooperating raw SQLite connection for fault injection.
    let other = Connection::open(directory.path().join("client.sqlite")).unwrap();
    other.execute_batch("BEGIN IMMEDIATE").unwrap();
    store
        .call(|c| {
            c.busy_timeout(Duration::from_millis(1))?;
            Ok(())
        })
        .await
        .unwrap();
    assert!(
        store
            .commit_local_record_with_outbox(fixture(7, 2))
            .await
            .is_err()
    );
    other.execute_batch("ROLLBACK").unwrap();
    assert_eq!(store.stats().await.unwrap().objects, 0);
    store.close().await.unwrap();
}

#[tokio::test]
async fn claim_retry_and_late_callback_use_attempt_numbers() {
    let directory = TempDir::new().unwrap();
    let store = ClientStore::open(directory.path()).await.unwrap();
    store
        .commit_local_record_with_outbox(fixture(8, 1))
        .await
        .unwrap();
    assert!(store.claim_next(time(99)).await.unwrap().is_none());
    let first = store.claim_next(time(100)).await.unwrap().unwrap();
    assert_eq!(first.number(), 1);
    assert!(store.claim_next(time(100)).await.unwrap().is_none());
    store
        .retry(first, time(500), RetryReason::Timeout)
        .await
        .unwrap();
    assert!(store.claim_next(time(499)).await.unwrap().is_none());
    let second = store.claim_next(time(500)).await.unwrap().unwrap();
    assert_eq!(second.number(), 2);
    assert!(matches!(
        store.retry(first, time(600), RetryReason::Timeout).await,
        Err(StoreError::StaleAttempt)
    ));
    store
        .retry(second, time(600), RetryReason::NetworkUnavailable)
        .await
        .unwrap();
    store.close().await.unwrap();
}

#[tokio::test]
async fn locator_upload_is_claimed_before_its_message_body() {
    let directory = TempDir::new().unwrap();
    let store = ClientStore::open(directory.path()).await.unwrap();
    let mut body = fixture(81, 1);
    body.metadata = RecordMetadata::new(
        "chat.message",
        body.metadata.space_id(),
        body.metadata.stream_id(),
        body.metadata.config_id(),
    )
    .unwrap();
    let mut locator = fixture(82, 1);
    locator.metadata = RecordMetadata::new(
        "chat.locator",
        locator.metadata.space_id(),
        locator.metadata.stream_id(),
        locator.metadata.config_id(),
    )
    .unwrap();
    store.commit_local_record_with_outbox(body).await.unwrap();
    store
        .commit_local_record_with_outbox(locator.clone())
        .await
        .unwrap();
    assert_eq!(
        store
            .claim_next(time(100))
            .await
            .unwrap()
            .unwrap()
            .record_id(),
        locator.record_id
    );
}

#[tokio::test]
async fn restart_requeues_inflight_without_resetting_attempt_counter() {
    let directory = TempDir::new().unwrap();
    let store = ClientStore::open(directory.path()).await.unwrap();
    let input = fixture(9, 1);
    store
        .commit_local_record_with_outbox(input.clone())
        .await
        .unwrap();
    let first = store.claim_next(time(100)).await.unwrap().unwrap();
    store.close().await.unwrap();
    let store = ClientStore::open(directory.path()).await.unwrap();
    assert_eq!(store.stats().await.unwrap().pending, 1);
    let second = store.claim_next(time(100)).await.unwrap().unwrap();
    assert_eq!(second.object_id(), first.object_id());
    assert_eq!(second.number(), 2);
    assert!(matches!(
        store.retry(first, time(100), RetryReason::Timeout).await,
        Err(StoreError::StaleAttempt)
    ));
    store.close().await.unwrap();
}

#[tokio::test]
async fn held_work_survives_restart_and_is_not_scheduled() {
    let directory = TempDir::new().unwrap();
    let store = ClientStore::open(directory.path()).await.unwrap();
    let input = fixture(10, 2);
    store
        .commit_local_record_with_outbox(input.clone())
        .await
        .unwrap();
    let attempt = store.claim_next(time(100)).await.unwrap().unwrap();
    assert_eq!(store.hold_record(input.record_id).await.unwrap(), 2);
    assert!(matches!(
        store.retry(attempt, time(100), RetryReason::Timeout).await,
        Err(StoreError::StaleAttempt)
    ));
    assert!(store.claim_next(time(999)).await.unwrap().is_none());
    store.close().await.unwrap();
    let store = ClientStore::open(directory.path()).await.unwrap();
    assert_eq!(store.stats().await.unwrap().held, 2);
    assert!(store.list_due(time(999), 128).await.unwrap().is_empty());
    assert!(store.get_object(input.object_id).await.unwrap().is_some());
    store.close().await.unwrap();
}

#[tokio::test]
async fn a_receipt_state_for_one_target_does_not_finish_the_other() {
    let directory = TempDir::new().unwrap();
    let store = ClientStore::open(directory.path()).await.unwrap();
    store
        .commit_local_record_with_outbox(fixture(11, 2))
        .await
        .unwrap();
    let attempt = store.claim_next(time(100)).await.unwrap().unwrap();
    // SQL-state fixture only. T04 must implement and verify actual signed receipts.
    store
        .call(move |c| {
            c.execute(
                "UPDATE outbox SET state='STORED', receipt_record=X'00'
            WHERE object_id=?1 AND peer_id=?2 AND mailbox_id=?3",
                params![
                    attempt.object_id.to_string(),
                    attempt.target.peer_id.to_string(),
                    attempt.target.mailbox_id.to_string(),
                ],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    let stats = store.stats().await.unwrap();
    assert_eq!((stats.stored, stats.pending), (1, 1));
    store.close().await.unwrap();
}

#[tokio::test]
async fn no_target_is_a_valid_local_only_commit() {
    let directory = TempDir::new().unwrap();
    let store = ClientStore::open(directory.path()).await.unwrap();
    store
        .commit_local_record_with_outbox(fixture(12, 0))
        .await
        .unwrap();
    let stats = store.stats().await.unwrap();
    assert_eq!((stats.records, stats.pending), (1, 0));
    store.close().await.unwrap();
}

#[tokio::test]
async fn only_one_worker_can_own_a_directory_and_close_releases_it() {
    let directory = TempDir::new().unwrap();
    let first = ClientStore::open(directory.path()).await.unwrap();
    assert!(matches!(
        ClientStore::open(directory.path()).await,
        Err(StoreError::AlreadyOpen)
    ));
    first.close().await.unwrap();
    assert!(matches!(first.stats().await, Err(StoreError::Closed)));
    ClientStore::open(directory.path())
        .await
        .unwrap()
        .close()
        .await
        .unwrap();
}

#[tokio::test]
async fn invalid_query_limits_are_rejected() {
    let directory = TempDir::new().unwrap();
    let store = ClientStore::open(directory.path()).await.unwrap();
    assert!(store.list_due(time(1), 0).await.is_err());
    assert!(store.list_due(time(1), 129).await.is_err());
    store.close().await.unwrap();
}

#[tokio::test]
async fn unknown_or_replica_schema_is_not_adopted() {
    for mode in ["foreign", "future", "replica"] {
        let directory = TempDir::new().unwrap();
        let database = directory.path().join("client.sqlite");
        let raw = Connection::open(database).unwrap();
        match mode {
            "foreign" => raw.execute_batch("CREATE TABLE unrelated(x)").unwrap(),
            "future" => raw.execute_batch("PRAGMA user_version=999").unwrap(),
            _ => raw
                .execute_batch(include_str!("../../../../migrations/001_replica.sql"))
                .unwrap(),
        }
        drop(raw);
        assert!(ClientStore::open(directory.path()).await.is_err());
    }
}

#[tokio::test]
async fn existing_canonical_v1_database_is_accepted() {
    let directory = TempDir::new().unwrap();
    let raw = Connection::open(directory.path().join("client.sqlite")).unwrap();
    raw.execute_batch(MIGRATION).unwrap();
    drop(raw);
    ClientStore::open(directory.path())
        .await
        .unwrap()
        .close()
        .await
        .unwrap();
}

#[tokio::test]
async fn modified_ciphertext_is_detected_on_read() {
    let directory = TempDir::new().unwrap();
    let store = ClientStore::open(directory.path()).await.unwrap();
    let input = fixture(13, 0);
    store
        .commit_local_record_with_outbox(input.clone())
        .await
        .unwrap();
    store
        .call(|c| {
            // Simulate an actor who bypasses the storage API. Never a public feature.
            c.execute_batch(
                "DROP TRIGGER objects_no_update; UPDATE objects
            SET ciphertext=zeroblob(size_bytes);",
            )?;
            Ok(())
        })
        .await
        .unwrap();
    assert!(matches!(
        store.get_object(input.object_id).await,
        Err(StoreError::ObjectIntegrity)
    ));
    store.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_duplicate_commits_have_one_winner() {
    let directory = TempDir::new().unwrap();
    let store = ClientStore::open(directory.path()).await.unwrap();
    let mut tasks = Vec::new();
    for _ in 0..24 {
        let store = store.clone();
        tasks.push(tokio::spawn(async move {
            store
                .commit_local_record_with_outbox(fixture(14, 2))
                .await
                .unwrap()
                .disposition
        }));
    }
    let mut inserted = 0;
    for task in tasks {
        if task.await.unwrap() == CommitDisposition::Inserted {
            inserted += 1;
        }
    }
    assert_eq!(inserted, 1);
    assert_eq!(store.stats().await.unwrap().pending, 2);
    store.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelling_an_admitted_awaiter_does_not_imply_rollback() {
    let directory = TempDir::new().unwrap();
    let store = ClientStore::open(directory.path()).await.unwrap();
    let (entered, observed) = oneshot::channel();
    let (release, blocked) = std::sync::mpsc::channel();
    let worker = store.clone();
    let task = tokio::spawn(async move {
        worker
            .call(move |c| {
                let _ = entered.send(());
                blocked.recv().unwrap();
                commit_local(c, &fixture(15, 2))
            })
            .await
    });
    tokio::time::timeout(Duration::from_secs(5), observed)
        .await
        .unwrap()
        .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    release.send(()).unwrap();
    assert_eq!(store.stats().await.unwrap().records, 1);
    assert_eq!(
        store
            .commit_local_record_with_outbox(fixture(15, 2))
            .await
            .unwrap()
            .disposition,
        CommitDisposition::AlreadyPresent
    );
    store.close().await.unwrap();
}

// The child exits without SQLite/worker destructors. Environment variables are
// read only by this TEST executable; the shipped library/CLI has no crash switch.
#[test]
fn crash_child() {
    let Ok(mode) = std::env::var("ELO_T01_TEST_CRASH_MODE") else {
        return;
    };
    let directory = std::env::var_os("ELO_T01_TEST_DIR").unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let store = ClientStore::open(PathBuf::from(directory)).await.unwrap();
        if mode == "before" {
            store
                .call::<(), _>(|c| {
                    let transaction =
                        c.transaction_with_behavior(TransactionBehavior::Immediate)?;
                    write_local_rows(&transaction, &fixture(16, 2))?;
                    std::process::exit(83)
                })
                .await
                .unwrap();
        } else {
            store
                .commit_local_record_with_outbox(fixture(16, 2))
                .await
                .unwrap();
            std::process::exit(84);
        }
    });
}

#[test]
fn process_exit_before_vs_after_commit() {
    for (mode, code, expected) in [("before", 83, 0_u64), ("after", 84, 1_u64)] {
        let directory = TempDir::new().unwrap();
        let output = ProcessCommand::new(std::env::current_exe().unwrap())
            .args(["--exact", "store::tests::crash_child", "--nocapture"])
            .env("ELO_T01_TEST_CRASH_MODE", mode)
            .env("ELO_T01_TEST_DIR", directory.path())
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(code),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let store = ClientStore::open(directory.path()).await.unwrap();
            let stats = store.stats().await.unwrap();
            assert_eq!(
                (stats.objects, stats.records, stats.sources, stats.pending),
                (expected, expected, expected, expected * 2)
            );
            store.close().await.unwrap();
        });
    }
}

#[tokio::test]
async fn message_projection_requires_real_queue_and_all_target_receipts() {
    let directory = TempDir::new().unwrap();
    let store = ClientStore::open(directory.path()).await.unwrap();
    let mut local = fixture(51, 0);
    local.metadata = RecordMetadata::new(
        "chat.message",
        local.metadata.space_id(),
        local.metadata.stream_id(),
        local.metadata.config_id(),
    )
    .unwrap();
    let mut queued = fixture(52, 2);
    queued.metadata = local.metadata.clone();
    store
        .commit_local_record_with_outbox(local.clone())
        .await
        .unwrap();
    store
        .commit_local_record_with_outbox(queued.clone())
        .await
        .unwrap();
    async fn status(store: &ClientStore, input: &PreparedLocalRecord) -> String {
        store
            .display_sources(SpaceId::from_bytes([1; 32]), StreamId::from_bytes([2; 16]))
            .await
            .unwrap()
            .into_iter()
            .find(|source| source.record == input.record_id)
            .unwrap()
            .status
    }
    assert_eq!(status(&store, &local).await, "LOCAL");
    assert_eq!(status(&store, &queued).await, "QUEUED");
    let attempt = store.claim_next(time(100)).await.unwrap().unwrap();
    assert_eq!(status(&store, &queued).await, "QUEUED");
    store
        .retry(attempt, time(500), RetryReason::NetworkUnavailable)
        .await
        .unwrap();
    assert_eq!(status(&store, &queued).await, "QUEUED");
    // Storage-projection fixture only; app/transport integrations verify real signed receipts.
    store
        .call(move |c| {
            c.execute(
                "UPDATE outbox SET state='STORED',receipt_record=X'00' WHERE peer_id=?1",
                [attempt.target.peer_id.to_string()],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(status(&store, &queued).await, "QUEUED");
    store
        .call(|c| {
            c.execute("UPDATE outbox SET state='STORED',receipt_record=X'00'", [])?;
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(status(&store, &queued).await, "STORED");
    assert_eq!(status(&store, &local).await, "LOCAL");
    store.close().await.unwrap();
    let store = ClientStore::open(directory.path()).await.unwrap();
    assert_eq!(status(&store, &queued).await, "STORED");
    assert_eq!(status(&store, &local).await, "LOCAL");
    // Losing one acknowledged copy must stop presenting the aggregate as synced.
    store.call(|c| {
        c.execute("INSERT INTO replica_copies(peer_id,mailbox_id,object_id,size_bytes,transfer_hint,missing) SELECT peer_id,mailbox_id,object_id,80,'eager',1 FROM outbox LIMIT 1", [])?;
        Ok(())
    }).await.unwrap();
    assert_eq!(status(&store, &queued).await, "REPAIR_PENDING");
    store
        .call(|c| {
            c.execute("UPDATE outbox SET state='PENDING'", [])?;
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(status(&store, &queued).await, "REPAIR_PENDING");
    store.hold_record(queued.record_id).await.unwrap();
    assert_eq!(status(&store, &queued).await, "HELD_STALE_CONFIG");
    store.call(|c| {
        c.execute("UPDATE outbox SET state='REJECTED' WHERE peer_id=(SELECT min(peer_id) FROM outbox)", [])?;
        Ok(())
    }).await.unwrap();
    assert_eq!(status(&store, &queued).await, "REJECTED");
    // Global inbox rejections are unrelated; only this record's own outbox affects it.
    assert_eq!(status(&store, &local).await, "LOCAL");
    assert_eq!(
        store.get_object(queued.object_id).await.unwrap(),
        Some(queued.ciphertext)
    );
    let local_id = local.record_id.to_string();
    store
        .call(move |c| {
            c.execute(
                "UPDATE records SET status='ACCEPTED' WHERE record_id=?1",
                [local_id],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(status(&store, &local).await, "ACCEPTED");
    store
        .call(|c| {
            c.execute("UPDATE records SET status='REJECTED'", [])?;
            Ok(())
        })
        .await
        .unwrap();
    assert!(
        store
            .display_sources(SpaceId::from_bytes([1; 32]), StreamId::from_bytes([2; 16]))
            .await
            .unwrap()
            .is_empty()
    );
    store.close().await.unwrap();
}
