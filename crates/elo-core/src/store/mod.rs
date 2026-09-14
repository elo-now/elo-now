//! One connection, one dedicated OS thread, a bounded async command queue.
//!
//! Cancellation AFTER enqueue does not cancel a transaction. If the response is
//! lost, retry the SAME PreparedLocalRecord. Do not infer rollback or create a new
//! event. A successful response is sent only after SQLite commit succeeds.
//!
//! Only one cooperating process may open a client directory. The OS file lock
//! prevents a second process from requeuing a live worker's INFLIGHT deliveries.
//! It is not a defense against a malicious process running as the same OS user.

mod audit;
mod backup;
pub(crate) use backup::MessageBackupPlan;
mod inbox;
pub use audit::TransportFailure;
mod model;
mod notifications;
mod presentation;
mod repair;
pub use inbox::{DisplaySource, InboxItem, PeerCursor};
#[cfg(test)]
mod tests;

use model::QUEUE_CAPACITY;
pub use model::{
    CommitDisposition, CommitResult, DeliveryAttempt, DeliveryTarget, LocalTime,
    MAX_INITIAL_TARGETS, MAX_OBJECT_BYTES, MAX_QUERY_LIMIT, PendingDelivery, PreparedLocalRecord,
    RecordMetadata, RetryReason, StoreStats,
};

use std::{
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

use fs2::FileExt;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};

use crate::ids::{InvalidId, ObjectId, RecordId};

const MIGRATION: &str = include_str!("../../../../migrations/001_client.sql");
const INBOX_MIGRATION: &str = include_str!("../../../../migrations/002_client_inbox.sql");
const AUTHORITY_MIGRATION: &str = include_str!("../../../../migrations/003_client_authority.sql");
const REPAIR_MIGRATION: &str = include_str!("../../../../migrations/004_client_repairs.sql");
const AUDIT_MIGRATION: &str = include_str!("../../../../migrations/005_client_message_audit.sql");
const NOTIFICATION_MIGRATION: &str =
    include_str!("../../../../migrations/006_client_notifications.sql");
const SCHEMA_VERSION: i64 = 6;
const INSERT_OBJECT: &str = include_str!("sql/insert_object.sql");
const INSERT_RECORD: &str = include_str!("sql/insert_record.sql");
const INSERT_SOURCE: &str = include_str!("sql/insert_source.sql");
const INSERT_TARGET: &str = include_str!("sql/insert_target.sql");
const GET_RECORD: &str = include_str!("sql/get_record.sql");
const GET_OBJECT: &str = include_str!("sql/get_object.sql");
const GET_DIRECT_SOURCES: &str = include_str!("sql/get_direct_sources.sql");
const GET_TARGETS: &str = include_str!("sql/get_targets.sql");
const STATS: &str = include_str!("sql/stats.sql");
const LIST_DUE: &str = include_str!("sql/list_due.sql");
const CLAIM: &str = include_str!("sql/claim.sql");
const RETRY: &str = include_str!("sql/retry.sql");
const RECOVER_INFLIGHT: &str = include_str!("sql/recover_inflight.sql");
const HOLD_RECORD: &str = include_str!("sql/hold_record.sql");
const SCHEMA: &str = include_str!("sql/schema.sql");

type Result<T> = std::result::Result<T, StoreError>;

// SQLite INTEGER is signed; keep the public counters unsigned without wrapping.
fn read_count(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<u64> {
    let value: i64 = row.get(index)?;
    u64::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(index, value))
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("profile backup is too large")]
    BackupTooLarge,
    #[error("invalid storage input: {0}")]
    InvalidInput(&'static str),
    #[error("invalid identifier in local database: {0}")]
    InvalidIdentifier(#[from] InvalidId),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("SQLite error (no local success confirmed): {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("client directory is already open by another worker/process")]
    AlreadyOpen,
    #[error("unsupported schema version {found}; expected 6")]
    UnsupportedSchema { found: i64 },
    #[error("database is not an unmodified elo.now client schema; refusing to adopt it")]
    UnrecognizedSchema,
    #[error("required SQLite configuration could not be verified")]
    InvalidPragmas,
    #[error("stored object does not match its content identifier")]
    ObjectIntegrity,
    #[error("retry differs from the original local commit: {0}")]
    IdempotencyConflict(&'static str),
    #[error("store is closed; operation was not enqueued")]
    Closed,
    #[error("worker response lost; outcome is unknown; retry the exact same input")]
    OutcomeUnknown,
    #[error("delivery attempt is stale or no longer INFLIGHT")]
    StaleAttempt,
}

type Job = Box<dyn FnOnce(&mut Connection) + Send + 'static>;

enum Command {
    Run(Job),
    Shutdown(oneshot::Sender<Result<()>>),
}

/// Clones share ONE writer; they do not open additional SQLite connections.
#[derive(Clone)]
pub struct ClientStore {
    sender: mpsc::Sender<Command>,
}

impl ClientStore {
    /// A consistent SQLite image from the writer, including committed WAL data.
    /// Only encrypted content and the existing database metadata are copied.
    pub async fn backup_image(&self, maximum: usize) -> Result<Vec<u8>> {
        self.call(move |connection| {
            let pages = connection.query_row("PRAGMA page_count", [], |row| read_count(row, 0))?;
            let size = connection.query_row("PRAGMA page_size", [], |row| read_count(row, 0))?;
            if pages.saturating_mul(size) > maximum as u64 {
                return Err(StoreError::InvalidInput("profile backup is too large"));
            }
            let image = connection.serialize("main")?;
            if image.len() > maximum {
                return Err(StoreError::InvalidInput("profile backup is too large"));
            }
            Ok(image.to_vec())
        })
        .await
    }

    /// Creates/opens `client.sqlite` in an explicit local directory.
    /// No SQL or filesystem work occurs on the caller's Tokio thread.
    pub async fn open(data_dir: impl AsRef<Path>) -> Result<Self> {
        let path = data_dir.as_ref().to_path_buf();
        let (sender, receiver) = mpsc::channel(QUEUE_CAPACITY);
        let (ready_sender, ready_receiver) = oneshot::channel();
        let _worker = thread::Builder::new()
            .name("elo-sqlite".into())
            .spawn(move || run_worker(path, receiver, ready_sender))?;
        ready_receiver
            .await
            .map_err(|_| StoreError::OutcomeUnknown)??;
        Ok(Self { sender })
    }

    async fn call<T, F>(&self, operation: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> Result<T> + Send + 'static,
    {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(Command::Run(Box::new(move |connection| {
                let result = operation(connection);
                // A dropped awaiter must NOT undo a completed local commit.
                let _ = reply.send(result);
            })))
            .await
            .map_err(|_| StoreError::Closed)?;
        response.await.map_err(|_| StoreError::OutcomeUnknown)?
    }

    pub async fn commit_local_record_with_outbox(
        &self,
        input: PreparedLocalRecord,
    ) -> Result<CommitResult> {
        self.call(move |connection| commit_local(connection, &input))
            .await
    }

    /// Checks the content hash again before returning the bytes to the caller.
    /// No decryption or signature verification is implied.
    pub async fn get_object(&self, id: ObjectId) -> Result<Option<Vec<u8>>> {
        self.call(move |connection| get_object(connection, id))
            .await
    }

    pub async fn stats(&self) -> Result<StoreStats> {
        self.call(|connection| {
            Ok(connection.query_row(STATS, [], |row| {
                Ok(StoreStats {
                    objects: read_count(row, 0)?,
                    records: read_count(row, 1)?,
                    sources: read_count(row, 2)?,
                    pending: read_count(row, 3)?,
                    inflight: read_count(row, 4)?,
                    stored: read_count(row, 5)?,
                    held: read_count(row, 6)?,
                    rejected: read_count(row, 7)?,
                })
            })?)
        })
        .await
    }

    /// Returns metadata only; it never copies 128 ciphertexts into a list.
    pub async fn list_due(&self, now: LocalTime, limit: usize) -> Result<Vec<PendingDelivery>> {
        if !(1..=MAX_QUERY_LIMIT).contains(&limit) {
            return Err(StoreError::InvalidInput("query limit must be 1..=128"));
        }
        self.call(move |connection| list_due(connection, now, limit))
            .await
    }

    /// Claim is only a scheduling primitive. Future sync MUST check current
    /// authorization before using it. T01 itself never performs network sends.
    pub async fn claim_next(&self, now: LocalTime) -> Result<Option<DeliveryAttempt>> {
        self.call(move |connection| {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let Some(job) = list_due(&transaction, now, 1)?.into_iter().next() else {
                transaction.commit()?;
                return Ok(None);
            };
            let number = job
                .attempts
                .checked_add(1)
                .ok_or(StoreError::InvalidInput("attempt counter exhausted"))?;
            let changed = transaction.execute(
                CLAIM,
                params![
                    job.object_id.to_string(),
                    job.target.peer_id.to_string(),
                    job.target.mailbox_id.to_string(),
                    job.attempts,
                ],
            )?;
            if changed != 1 {
                return Err(StoreError::StaleAttempt);
            }
            let mut event = audit::Event::new("UPLOAD_STARTED", Some(job.target));
            event.attempt = Some(number);
            audit::append(&transaction, job.record_id, audit::clock()?, &event)?;
            transaction.commit()?;
            Ok(Some(DeliveryAttempt {
                record_id: job.record_id,
                object_id: job.object_id,
                target: job.target,
                number,
            }))
        })
        .await
    }

    pub async fn retry(
        &self,
        attempt: DeliveryAttempt,
        next: LocalTime,
        reason: RetryReason,
    ) -> Result<()> {
        self.retry_with_diagnostics(attempt, next, reason, None)
            .await
    }

    pub(crate) async fn retry_with_diagnostics(
        &self,
        attempt: DeliveryAttempt,
        next: LocalTime,
        reason: RetryReason,
        failure: Option<TransportFailure>,
    ) -> Result<()> {
        self.call(move |connection| {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let changed = transaction.execute(
                RETRY,
                params![
                    attempt.object_id.to_string(),
                    attempt.target.peer_id.to_string(),
                    attempt.target.mailbox_id.to_string(),
                    attempt.number,
                    next.as_millis(),
                    reason.as_str(),
                ],
            )?;
            if changed != 1 {
                return Err(StoreError::StaleAttempt);
            }
            let mut event = audit::Event::new("RETRY_SCHEDULED", Some(attempt.target));
            event.attempt = Some(attempt.number);
            event.failure = failure;
            event.next_retry = Some(next);
            audit::append(&transaction, attempt.record_id, audit::clock()?, &event)?;
            transaction.commit()?;
            Ok(())
        })
        .await
    }

    /// Preserve local bytes; suspend pending/inflight deliveries, not STORED.
    /// There is deliberately no public "unhold" bypass for future auth checks.
    pub async fn hold_record(&self, id: RecordId) -> Result<usize> {
        self.call(move |connection| {
            let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let changed = tx.execute(HOLD_RECORD, [id.to_string()])?;
            if changed > 0 {
                audit::append(&tx, id, audit::clock()?, &audit::Event::new("HELD", None))?;
            }
            tx.commit()?;
            Ok(changed)
        })
        .await
    }

    /// Stops this store and ALL clones. Drains admitted commands, closes the
    /// connection and releases the OS lock before acknowledging shutdown.
    /// Dropping all handles also stops the worker, but without a completion ack.
    pub async fn close(&self) -> Result<()> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(Command::Shutdown(reply))
            .await
            .map_err(|_| StoreError::Closed)?;
        response.await.map_err(|_| StoreError::OutcomeUnknown)?
    }
}

fn run_worker(
    data_dir: PathBuf,
    mut receiver: mpsc::Receiver<Command>,
    ready: oneshot::Sender<Result<()>>,
) {
    let (mut connection, lock) = match open_connection(&data_dir) {
        Ok(opened) => opened,
        Err(error) => {
            let _ = ready.send(Err(error));
            return;
        }
    };
    if ready.send(Ok(())).is_err() {
        drop(connection);
        drop(lock);
        return;
    }
    while let Some(command) = receiver.blocking_recv() {
        match command {
            Command::Run(operation) => operation(&mut connection),
            Command::Shutdown(reply) => {
                receiver.close();
                // Commands accepted before close may already be in the queue.
                while let Some(queued) = receiver.blocking_recv() {
                    match queued {
                        Command::Run(operation) => operation(&mut connection),
                        Command::Shutdown(other) => {
                            let _ = other.send(Err(StoreError::Closed));
                        }
                    }
                }
                let result = connection
                    .close()
                    .map_err(|(_connection, error)| StoreError::Sqlite(error));
                // A concurrent fork can briefly inherit this open file
                // description before exec closes CLOEXEC descriptors. Closing
                // only our descriptor would leave its flock held in that child.
                // Explicit unlock must precede the successful close reply.
                let unlocked = FileExt::unlock(&lock).map_err(StoreError::Io);
                drop(lock);
                let _ = reply.send(result.and(unlocked));
                return;
            }
        }
    }
    // Keep the lock until AFTER the connection has been dropped/checkpointed.
    drop(connection);
    drop(lock);
}

fn private_file(path: &Path) -> Result<File> {
    if fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        return Err(StoreError::InvalidInput(
            "database/lock path must not be a symlink",
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(options.open(path)?)
}

fn open_connection(data_dir: &Path) -> Result<(Connection, File)> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(data_dir)?;
    let directory = data_dir.canonicalize()?;
    let lock = private_file(&directory.join(".elo-client.lock"))?;
    match FileExt::try_lock_exclusive(&lock) {
        Ok(()) => {}
        Err(error)
            if error.kind() == std::io::ErrorKind::WouldBlock
                || error.raw_os_error() == fs2::lock_contended_error().raw_os_error() =>
        {
            return Err(StoreError::AlreadyOpen);
        }
        Err(error) => return Err(StoreError::Io(error)),
    }
    let path = directory.join("client.sqlite");
    drop(private_file(&path)?);
    let connection = Connection::open(path)?;
    connection.busy_timeout(Duration::from_millis(5_000))?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.pragma_update(None, "trusted_schema", "OFF")?;
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let schema = read_schema(&connection)?;
    match version {
        0 if schema.is_empty() => {}
        1 | 2 | 3 | 4 | 5 | SCHEMA_VERSION => validate_schema(&connection)?,
        0 => return Err(StoreError::UnrecognizedSchema),
        found => return Err(StoreError::UnsupportedSchema { found }),
    }
    let mode: String = connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
    if !mode.eq_ignore_ascii_case("wal") {
        let actual: String =
            connection.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
        if !actual.eq_ignore_ascii_case("wal") {
            return Err(StoreError::InvalidPragmas);
        }
    }
    connection.pragma_update(None, "synchronous", "FULL")?;
    verify_pragmas(&connection)?;
    if version == 0 {
        // The original migration owns its BEGIN/COMMIT. Do not nest it.
        connection.execute_batch(MIGRATION)?;
    }
    if version < 2 {
        connection.execute_batch(INBOX_MIGRATION)?;
    }
    if version < 3 {
        connection.execute_batch(AUTHORITY_MIGRATION)?;
    }
    if version < 4 {
        connection.execute_batch(REPAIR_MIGRATION)?;
    }
    if version < 5 {
        connection.execute_batch(AUDIT_MIGRATION)?;
    }
    if version < 6 {
        connection.execute_batch(NOTIFICATION_MIGRATION)?;
    }
    validate_schema(&connection)?;
    let integrity: String = connection.query_row("PRAGMA quick_check(1)", [], |row| row.get(0))?;
    let foreign_key_errors: i64 =
        connection.query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })?;
    if integrity != "ok" || foreign_key_errors != 0 {
        return Err(StoreError::UnrecognizedSchema);
    }
    // Cooperating writers cannot still own live attempts because of our OS lock.
    let tx = connection.unchecked_transaction()?;
    {
        let mut q = tx.prepare(
            "SELECT record_id,peer_id,mailbox_id,attempts FROM outbox WHERE state='INFLIGHT'",
        )?;
        let rows = q
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for (record, peer, mailbox, attempt) in rows {
            let mut event = audit::Event::new(
                "PROCESS_RESTART",
                Some(DeliveryTarget {
                    peer_id: peer.parse()?,
                    mailbox_id: mailbox.parse()?,
                }),
            );
            event.attempt = Some(attempt);
            audit::append(&tx, record.parse()?, audit::clock()?, &event)?;
        }
    }
    tx.execute(RECOVER_INFLIGHT, [])?;
    tx.commit()?;
    Ok((connection, lock))
}

fn verify_pragmas(connection: &Connection) -> Result<()> {
    let mode: String = connection.pragma_query_value(None, "journal_mode", |r| r.get(0))?;
    let fk: i64 = connection.pragma_query_value(None, "foreign_keys", |r| r.get(0))?;
    let sync: i64 = connection.pragma_query_value(None, "synchronous", |r| r.get(0))?;
    let timeout: i64 = connection.pragma_query_value(None, "busy_timeout", |r| r.get(0))?;
    if mode.eq_ignore_ascii_case("wal") && fk == 1 && sync == 2 && timeout == 5_000 {
        Ok(())
    } else {
        Err(StoreError::InvalidPragmas)
    }
}

type SchemaEntry = (String, String, String, Option<String>);

fn read_schema(connection: &Connection) -> Result<Vec<SchemaEntry>> {
    let mut statement = connection.prepare(SCHEMA)?;
    let rows = statement.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

fn validate_schema(connection: &Connection) -> Result<()> {
    // Validate the exact old schema before applying any migration.
    let expected = Connection::open_in_memory()?;
    expected.execute_batch(MIGRATION)?;
    let version: i64 = connection.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if version >= 2 {
        expected.execute_batch(INBOX_MIGRATION)?;
    }
    if version >= 3 {
        expected.execute_batch(AUTHORITY_MIGRATION)?;
    }
    if version >= 4 {
        expected.execute_batch(REPAIR_MIGRATION)?;
    }
    if version >= 5 {
        expected.execute_batch(AUDIT_MIGRATION)?;
    }
    if version >= 6 {
        expected.execute_batch(NOTIFICATION_MIGRATION)?;
    }
    if read_schema(connection)? != read_schema(&expected)? {
        return Err(StoreError::UnrecognizedSchema);
    }
    Ok(())
}

fn get_object(connection: &Connection, id: ObjectId) -> Result<Option<Vec<u8>>> {
    let bytes: Option<Vec<u8>> = connection
        .query_row(GET_OBJECT, [id.to_string()], |r| r.get(0))
        .optional()?;
    if bytes.as_ref().is_some_and(|value| {
        value.is_empty() || value.len() > MAX_OBJECT_BYTES || ObjectId::of_ciphertext(value) != id
    }) {
        return Err(StoreError::ObjectIntegrity);
    }
    Ok(bytes)
}

fn commit_local(connection: &mut Connection, input: &PreparedLocalRecord) -> Result<CommitResult> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let disposition = write_local_rows(&transaction, input)?;
    transaction.commit()?;
    Ok(CommitResult {
        record_id: input.record_id,
        object_id: input.object_id,
        disposition,
        target_count: input.targets.len(),
    })
}

type IndexedMetadata = (String, Option<String>, Option<String>, Option<String>);

fn indexed_metadata(input: &PreparedLocalRecord) -> IndexedMetadata {
    (
        input.metadata.kind().to_owned(),
        input.metadata.space_id().map(|id| id.to_string()),
        input.metadata.stream_id().map(|id| id.to_string()),
        input.metadata.config_id().map(|id| id.to_string()),
    )
}

/// Runs inside the caller's transaction; has no commit and no await.
fn write_local_rows(
    connection: &Connection,
    input: &PreparedLocalRecord,
) -> Result<CommitDisposition> {
    let existing: Option<IndexedMetadata> = connection
        .query_row(GET_RECORD, [input.record_id.to_string()], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })
        .optional()?;
    let metadata = indexed_metadata(input);
    if let Some(existing) = existing {
        if existing != metadata {
            return Err(StoreError::IdempotencyConflict("record metadata"));
        }
        let mut statement = connection.prepare(GET_DIRECT_SOURCES)?;
        let sources = statement
            .query_map([input.record_id.to_string()], |r| r.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if sources != vec![input.object_id.to_string()] {
            return Err(StoreError::IdempotencyConflict("ciphertext/direct source"));
        }
        if get_object(connection, input.object_id)?.as_deref() != Some(input.ciphertext.as_slice())
        {
            return Err(StoreError::ObjectIntegrity);
        }
        let mut statement = connection.prepare(GET_TARGETS)?;
        let targets = statement
            .query_map([input.object_id.to_string()], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let expected: Vec<_> = input
            .targets
            .iter()
            .map(|t| (t.peer_id.to_string(), t.mailbox_id.to_string()))
            .collect();
        if targets != expected {
            return Err(StoreError::IdempotencyConflict("initial delivery targets"));
        }
        return Ok(CommitDisposition::AlreadyPresent);
    }
    match get_object(connection, input.object_id)? {
        Some(bytes) if bytes != input.ciphertext => return Err(StoreError::ObjectIntegrity),
        Some(_) => {}
        None => {
            connection.execute(
                INSERT_OBJECT,
                params![
                    input.object_id.to_string(),
                    input.ciphertext.as_slice(),
                    input.ciphertext.len() as i64,
                    input.created.as_millis(),
                ],
            )?;
        }
    }
    connection.execute(
        INSERT_RECORD,
        params![
            input.record_id.to_string(),
            metadata.0,
            metadata.1,
            metadata.2,
            metadata.3,
            input.created.as_millis(),
        ],
    )?;
    connection.execute(
        INSERT_SOURCE,
        params![input.record_id.to_string(), input.object_id.to_string()],
    )?;
    for target in &input.targets {
        connection.execute(
            INSERT_TARGET,
            params![
                input.record_id.to_string(),
                input.object_id.to_string(),
                target.peer_id.to_string(),
                target.mailbox_id.to_string(),
                input.created.as_millis(),
            ],
        )?;
        audit::append(
            connection,
            input.record_id,
            input.created,
            &audit::Event::new("QUEUED", Some(*target)),
        )?;
    }
    Ok(CommitDisposition::Inserted)
}

fn list_due(connection: &Connection, now: LocalTime, limit: usize) -> Result<Vec<PendingDelivery>> {
    let mut statement = connection.prepare(LIST_DUE)?;
    let rows = statement.query_map(params![now.as_millis(), limit as i64], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, i64>(4)?,
            r.get::<_, i64>(5)?,
        ))
    })?;
    let mut deliveries = Vec::new();
    for row in rows {
        let (record, object, peer, mailbox, attempts, next_attempt_local_ms) = row?;
        deliveries.push(PendingDelivery {
            record_id: record.parse()?,
            object_id: object.parse()?,
            target: DeliveryTarget {
                peer_id: peer.parse()?,
                mailbox_id: mailbox.parse()?,
            },
            attempts,
            next_attempt_local_ms,
        });
    }
    Ok(deliveries)
}

pub(crate) use inbox::ConfigurationState;
