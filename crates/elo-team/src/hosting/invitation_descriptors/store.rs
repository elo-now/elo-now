//! Immutable, quota-bounded ciphertext storage. Authorization is deliberately
//! separate: callers must verify the owner, signed policy and fresh witness head
//! before committing an upload. No invitation seed enters this module.
use elo_core::ids::{ObjectId, RecordId, SpaceId, StreamId};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use std::{path::Path, time::Duration};

pub(crate) const MAX_CIPHERTEXT_BYTES: usize = elo_core::witness::link::MAX_CIPHERTEXT_BYTES;
pub(crate) const MAX_TTL_MS: u64 = 7 * 24 * 3_600_000;
const DAY_MS: u64 = 24 * 3_600_000;
const MAX_OBJECTS: u64 = 1024;
const MAX_OBJECTS_PER_SPACE: u64 = 8;
const MAX_BYTES: u64 = 128 * 1024 * 1024;
const MAX_BYTES_PER_SPACE: u64 = 8 * 1024 * 1024;
const DAILY_UPLOADS: u64 = 128;
const DAILY_UPLOADS_PER_SPACE: u64 = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Error {
    Invalid,
    Unauthorized,
    Conflict,
    Missing,
    Limit,
    Unavailable,
}
pub(crate) type Result<T> = std::result::Result<T, Error>;
impl From<rusqlite::Error> for Error {
    fn from(_: rusqlite::Error) -> Self {
        Self::Unavailable
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Binding {
    pub space: SpaceId,
    pub stream: StreamId,
    pub policy: RecordId,
    pub digest: ObjectId,
    pub size: u64,
    pub expires_at_ms: u64,
}

/// This is raw SHA-256, as used by the short-link codec. ObjectId's normal
/// domain-separated constructor must not be used for invitation ciphertext.
pub(crate) fn ciphertext_id(bytes: &[u8]) -> ObjectId {
    ObjectId::from_bytes(Sha256::digest(bytes).into())
}

pub(crate) struct Store {
    db: Connection,
}
impl Store {
    pub fn open(directory: &Path) -> Result<Self> {
        let metadata = std::fs::symlink_metadata(directory).map_err(|_| Error::Unavailable)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(Error::Invalid);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(Error::Invalid);
            }
        }
        let path = directory.join("invitations.sqlite");
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let candidate = directory.join(format!("invitations.sqlite{suffix}"));
            match std::fs::symlink_metadata(&candidate) {
                Ok(metadata) if !metadata.is_file() || metadata.file_type().is_symlink() => {
                    return Err(Error::Invalid);
                }
                Ok(metadata) => {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        if metadata.permissions().mode() & 0o077 != 0 {
                            return Err(Error::Invalid);
                        }
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(Error::Unavailable),
            }
        }
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(&path).map_err(|_| Error::Unavailable)?;
        let db = Connection::open(path)?;
        db.busy_timeout(Duration::from_millis(100))?;
        db.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
             PRAGMA max_page_count=40960; PRAGMA journal_size_limit=4194304;
             PRAGMA wal_autocheckpoint=32;
             CREATE TABLE IF NOT EXISTS ciphertexts(
                 digest TEXT PRIMARY KEY CHECK(length(digest)=64),
                 space TEXT NOT NULL CHECK(length(space)=64),
                 stream TEXT NOT NULL CHECK(length(stream)=32),
                 policy TEXT NOT NULL CHECK(length(policy)=64),
                 size INTEGER NOT NULL CHECK(size BETWEEN 113 AND 1048617),
                 expires INTEGER NOT NULL CHECK(expires>0),
                 body BLOB NOT NULL CHECK(length(body)=size)
             );
             CREATE INDEX IF NOT EXISTS ciphertext_expiry ON ciphertexts(expires);
             CREATE INDEX IF NOT EXISTS ciphertext_space ON ciphertexts(space);
             CREATE TABLE IF NOT EXISTS budgets(
                 day INTEGER NOT NULL, scope TEXT NOT NULL, count INTEGER NOT NULL,
                 PRIMARY KEY(day,scope)
             );
             CREATE TABLE IF NOT EXISTS clock(
                 singleton INTEGER PRIMARY KEY CHECK(singleton=1), highest INTEGER NOT NULL
             );
             INSERT OR IGNORE INTO clock VALUES(1,0);",
        )?;
        Ok(Self { db })
    }

    /// Identical retries do not consume storage or the daily creation budget.
    /// Existing ciphertext cannot be rebound to another policy, scope or expiry.
    pub fn put(&mut self, binding: &Binding, body: &[u8], now_ms: u64) -> Result<bool> {
        if !(113..=MAX_CIPHERTEXT_BYTES).contains(&body.len())
            || body[0] != 1
            || binding.size != body.len() as u64
            || ciphertext_id(body) != binding.digest
            || binding.expires_at_ms <= now_ms
            || binding.expires_at_ms > now_ms.saturating_add(MAX_TTL_MS)
            || binding.expires_at_ms > elo_core::record::MAX_INTEGER
        {
            return Err(Error::Invalid);
        }
        let transaction = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_time(&transaction, now_ms)?;
        let existing: Option<(String, String, String, i64, i64)> = transaction
            .query_row(
                "SELECT space,stream,policy,size,expires FROM ciphertexts WHERE digest=?1",
                [binding.digest.to_string()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()?;
        if let Some(existing) = existing {
            if existing
                != (
                    binding.space.to_string(),
                    binding.stream.to_string(),
                    binding.policy.to_string(),
                    binding.size as i64,
                    binding.expires_at_ms as i64,
                )
            {
                return Err(Error::Conflict);
            }
            let stored: Option<Vec<u8>> = transaction
                .query_row(
                    "SELECT body FROM ciphertexts WHERE digest=?1 AND length(body)=?2",
                    params![binding.digest.to_string(), binding.size as i64],
                    |row| row.get(0),
                )
                .optional()?;
            if stored.as_deref() != Some(body) {
                return Err(Error::Unavailable);
            }
            transaction.commit()?;
            return Ok(false);
        }
        transaction.execute("DELETE FROM ciphertexts WHERE expires<=?1", [now_ms as i64])?;
        let (count, bytes): (u32, u32) = transaction.query_row(
            "SELECT COUNT(*),COALESCE(SUM(size),0) FROM ciphertexts",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let (space_count, space_bytes): (u32, u32) = transaction.query_row(
            "SELECT COUNT(*),COALESCE(SUM(size),0) FROM ciphertexts WHERE space=?1",
            [binding.space.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if u64::from(count) >= MAX_OBJECTS
            || u64::from(space_count) >= MAX_OBJECTS_PER_SPACE
            || u64::from(bytes).saturating_add(binding.size) > MAX_BYTES
            || u64::from(space_bytes).saturating_add(binding.size) > MAX_BYTES_PER_SPACE
        {
            return Err(Error::Limit);
        }
        let day = (now_ms / DAY_MS) as i64;
        transaction.execute("DELETE FROM budgets WHERE day<?1", [day])?;
        for (scope, limit) in [
            ("*".to_owned(), DAILY_UPLOADS),
            (binding.space.to_string(), DAILY_UPLOADS_PER_SPACE),
        ] {
            let count: u32 = transaction.query_row(
                "SELECT COALESCE((SELECT count FROM budgets WHERE day=?1 AND scope=?2),0)",
                params![day, scope],
                |row| row.get(0),
            )?;
            if u64::from(count) >= limit {
                return Err(Error::Limit);
            }
            transaction.execute(
                "INSERT INTO budgets(day,scope,count) VALUES(?1,?2,1)
                 ON CONFLICT(day,scope) DO UPDATE SET count=count+1",
                params![day, scope],
            )?;
        }
        transaction.execute(
            "INSERT INTO ciphertexts(digest,space,stream,policy,size,expires,body) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![binding.digest.to_string(),binding.space.to_string(),binding.stream.to_string(),binding.policy.to_string(),binding.size as i64,binding.expires_at_ms as i64,body],
        )?;
        transaction.commit()?;
        Ok(true)
    }

    /// Expired bytes are unavailable immediately, independently of the worker.
    pub fn get(&mut self, digest: ObjectId, now_ms: u64) -> Result<Vec<u8>> {
        let transaction = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_time(&transaction, now_ms)?;
        let body: Option<Vec<u8>> = transaction.query_row(
            "SELECT body FROM ciphertexts WHERE digest=?1 AND expires>?2 AND size BETWEEN 113 AND 1048617 AND length(body)=size",
            params![digest.to_string(), now_ms as i64], |row| row.get(0),
        ).optional()?;
        transaction.commit()?;
        let body = body.ok_or(Error::Missing)?;
        if !(113..=MAX_CIPHERTEXT_BYTES).contains(&body.len()) || ciphertext_id(&body) != digest {
            return Err(Error::Unavailable);
        }
        Ok(body)
    }

    /// The hosting background worker calls this without waiting on a request.
    pub fn cleanup(&mut self, now_ms: u64) -> Result<usize> {
        let transaction = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_time(&transaction, now_ms)?;
        let removed =
            transaction.execute("DELETE FROM ciphertexts WHERE expires<=?1", [now_ms as i64])?;
        transaction.execute(
            "DELETE FROM budgets WHERE day<?1",
            [(now_ms / DAY_MS) as i64],
        )?;
        transaction.commit()?;
        Ok(removed)
    }
}

fn check_time(transaction: &rusqlite::Transaction<'_>, now_ms: u64) -> Result<()> {
    let highest: i64 =
        transaction.query_row("SELECT highest FROM clock WHERE singleton=1", [], |row| {
            row.get(0)
        })?;
    if now_ms > elo_core::record::MAX_INTEGER || (now_ms as i64) < highest || highest < 0 {
        return Err(Error::Unavailable);
    }
    transaction.execute(
        "UPDATE clock SET highest=?1 WHERE singleton=1",
        [now_ms as i64],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(super) fn private_test_directory() -> tempfile::TempDir {
    let mut builder = tempfile::Builder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(std::fs::Permissions::from_mode(0o700));
    }
    builder.tempdir().unwrap()
}
