//! A transaction journal is durable, but is not an independent rollback anchor.
//! Every process starts sealed; activation must come from independently retained evidence.
use crate::{
    Error, Result,
    wire::{Position, Receipt, Response},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::SigningKey;
use elo_core::{
    authority::WitnessPin,
    ids::{RecordId, SpaceId},
    record::{self, SignedRecord},
};
use fs2::FileExt;
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    path::Path,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const MAX_EVENTS: u64 = 1_000_000;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Activation {
    pub startup_nonce: String,
    pub expected_position: Position,
    pub public_key: String,
    pub key_generation: u64,
    pub expires_at_ms: u64,
}

#[derive(Serialize)]
pub struct Startup {
    pub startup_nonce: String,
    pub observed_position: Position,
    pub public_key: String,
    pub key_generation: u64,
}

pub struct Journal {
    pub(crate) db: Connection,
    pub(crate) key: SigningKey,
    pub(crate) pin: WitnessPin,
    _lock: File,
    startup_nonce: String,
    active: bool,
    clock_failed: bool,
    last_clock: u64,
    anchor_wall: u64,
    monotonic: Instant,
}

impl Journal {
    pub fn open(data: &Path, key_path: &Path, pin: WitnessPin, now: u64) -> Result<Self> {
        pin.validate()?;
        private_directory(data)?;
        let canonical_data = std::fs::canonicalize(data).map_err(|_| Error::Unavailable)?;
        let canonical_key = std::fs::canonicalize(key_path).map_err(|_| Error::Unavailable)?;
        if canonical_key.starts_with(&canonical_data) {
            return Err(Error::Invalid);
        }
        let raw = Zeroizing::new(
            elo_core::vault::read_private(key_path).map_err(|_| Error::Unavailable)?,
        );
        let seed: &[u8; 32] = raw.as_slice().try_into().map_err(|_| Error::Invalid)?;
        let key = SigningKey::from_bytes(seed);
        if record::encode_hex(key.verifying_key().as_bytes()) != pin.public_key
            || pin.key_generation == 0
        {
            return Err(Error::Invalid);
        }
        let lock = private_file(&data.join("witness.lock"))?;
        lock.try_lock_exclusive().map_err(|_| Error::Unavailable)?;
        let path = data.join("witness.sqlite");
        private_file(&path)?;
        for name in ["witness.sqlite-wal", "witness.sqlite-shm"] {
            let sidecar = data.join(name);
            if sidecar.exists() {
                private_file(&sidecar)?;
            }
        }
        let db = Connection::open(path)?;
        db.busy_timeout(Duration::from_secs(2))?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA max_page_count=262144;
          CREATE TABLE IF NOT EXISTS metadata(id INTEGER PRIMARY KEY CHECK(id=1), pin TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS events(sequence INTEGER PRIMARY KEY, record_id TEXT NOT NULL UNIQUE, receipt TEXT NOT NULL, request_id TEXT NOT NULL UNIQUE, response TEXT NOT NULL, space TEXT NOT NULL);
          CREATE INDEX IF NOT EXISTS events_space_sequence ON events(space,sequence DESC);
          CREATE TABLE IF NOT EXISTS spaces(space TEXT PRIMARY KEY, stream TEXT NOT NULL, proof TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS policies(space TEXT NOT NULL, id TEXT PRIMARY KEY, record TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0, uses INTEGER NOT NULL DEFAULT 0);
          CREATE INDEX IF NOT EXISTS policies_space_id ON policies(space,id);
          CREATE TABLE IF NOT EXISTS challenges(id TEXT PRIMARY KEY, space TEXT NOT NULL, policy TEXT NOT NULL, credential TEXT NOT NULL, record TEXT NOT NULL, expires INTEGER NOT NULL, intent TEXT);
          CREATE INDEX IF NOT EXISTS challenges_space_id ON challenges(space,id);
          CREATE UNIQUE INDEX IF NOT EXISTS challenges_durable_request ON challenges(space,intent) WHERE substr(intent,1,3)='v2:';
          CREATE TABLE IF NOT EXISTS tombstones(space TEXT NOT NULL, credential TEXT NOT NULL, identity TEXT NOT NULL, PRIMARY KEY(space,credential));
          CREATE TABLE IF NOT EXISTS command_nonces(credential TEXT NOT NULL, nonce TEXT NOT NULL, request TEXT NOT NULL, expires INTEGER NOT NULL, PRIMARY KEY(credential,nonce));
          CREATE TABLE IF NOT EXISTS registration_limits(ip TEXT NOT NULL, day INTEGER NOT NULL, count INTEGER NOT NULL, PRIMARY KEY(ip,day));")?;
        let pin_json = serde_json::to_string(&pin).map_err(|_| Error::Invalid)?;
        let existing: Option<String> = db
            .query_row("SELECT pin FROM metadata WHERE id=1", [], |r| r.get(0))
            .optional()?;
        if existing.as_ref().is_some_and(|old| old != &pin_json) {
            return Err(Error::RecoveryRequired);
        }
        db.execute(
            "INSERT OR IGNORE INTO metadata(id,pin) VALUES(1,?1)",
            [&pin_json],
        )?;
        if db.query_row("PRAGMA quick_check", [], |r| r.get::<_, String>(0))? != "ok" {
            return Err(Error::RecoveryRequired);
        }
        let mut previous = None;
        let mut sequence = 0;
        let mut time = 0;
        {
            let mut statement = db.prepare(
                "SELECT sequence,record_id,receipt,request_id,space FROM events ORDER BY sequence",
            )?;
            let mut rows = statement.query([])?;
            while let Some(row) = rows.next()? {
                let encoded: String = row.get(2)?;
                let record = decode(&encoded)?;
                record.verify_signature(&key.verifying_key())?;
                let body: Receipt = record.decode()?;
                sequence += 1;
                if sequence > MAX_EVENTS
                    || row.get::<_, i64>(0)? as u64 != sequence
                    || row.get::<_, String>(1)? != record.id().to_string()
                    || row.get::<_, String>(3)? != body.request_id.to_string()
                    || row.get::<_, String>(4)? != body.space_id.to_string()
                    || body.v != 1
                    || body.kind != "witness.receipt"
                    || body.audience != pin.url
                    || body.sequence != sequence
                    || body.previous != previous
                    || body.accepted_at_ms < time
                    || body.witness_key_generation != pin.key_generation
                {
                    return Err(Error::RecoveryRequired);
                }
                previous = Some(record.id());
                time = body.accepted_at_ms;
            }
        }
        if now < time {
            return Err(Error::RecoveryRequired);
        }
        verify_materialized(&db, &pin)?;
        Ok(Self {
            db,
            key,
            pin,
            _lock: lock,
            startup_nonce: record::random_hex::<32>()?,
            active: false,
            clock_failed: false,
            last_clock: now,
            anchor_wall: now,
            monotonic: Instant::now(),
        })
    }

    pub fn startup(&self) -> Result<Startup> {
        Ok(Startup {
            startup_nonce: self.startup_nonce.clone(),
            observed_position: position(&self.db)?,
            public_key: self.pin.public_key.clone(),
            key_generation: self.pin.key_generation,
        })
    }

    /// The caller must obtain expected_position from outside this host. Copying
    /// observed_position from this process does not establish rollback safety.
    pub fn activate(&mut self, activation: Activation, now: u64) -> Result<()> {
        if self.active
            || self.clock_failed
            || now < self.last_clock
            || activation.startup_nonce != self.startup_nonce
            || activation.public_key != self.pin.public_key
            || activation.key_generation != self.pin.key_generation
            || activation.expected_position != position(&self.db)?
            || activation.expires_at_ms < now
            || activation.expires_at_ms > now.saturating_add(600_000)
        {
            return Err(Error::RecoveryRequired);
        }
        verify_materialized(&self.db, &self.pin)?;
        self.last_clock = now;
        self.anchor_wall = now;
        self.monotonic = Instant::now();
        self.active = true;
        Ok(())
    }

    pub fn ready(&mut self, now: u64) -> bool {
        self.guard(now).is_ok()
    }

    pub(crate) fn guard(&mut self, now: u64) -> Result<()> {
        if now > record::MAX_INTEGER || !self.active {
            return Err(Error::RecoveryRequired);
        }
        let elapsed = self
            .monotonic
            .elapsed()
            .as_millis()
            .min(u128::from(u64::MAX)) as u64;
        let wall = now.saturating_sub(self.anchor_wall);
        if now < self.last_clock || wall.abs_diff(elapsed) > 5_000 {
            self.active = false;
            self.clock_failed = true;
            return Err(Error::RecoveryRequired);
        }
        self.last_clock = now;
        Ok(())
    }
}

pub(crate) fn position(db: &Connection) -> Result<Position> {
    Ok(db
        .query_row(
            "SELECT sequence,record_id FROM events ORDER BY sequence DESC LIMIT 1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?
        .map(|(sequence, id)| {
            Ok::<Position, Error>(Position {
                sequence: u64::try_from(sequence).map_err(|_| Error::Unavailable)?,
                record_id: Some(id.parse().map_err(|_| Error::Unavailable)?),
            })
        })
        .transpose()?
        .unwrap_or(Position {
            sequence: 0,
            record_id: None,
        }))
}

/// Hash ordered, typed SQL values instead of relying on SQLite's file layout or
/// unordered JSON objects. Every authority-bearing row belongs to one Space.
pub(crate) fn state_digest(db: &Connection, space: SpaceId) -> Result<String> {
    use rusqlite::types::ValueRef;
    let mut hash = Sha256::new();
    hash.update(b"elo.now/witness/materialized-state/v1\0");
    hash.update(space.as_bytes());
    for (table, query) in [
        (
            "spaces",
            "SELECT space,stream,proof FROM spaces WHERE space=?1 ORDER BY space",
        ),
        (
            "policies",
            "SELECT space,id,record,revoked,uses FROM policies WHERE space=?1 ORDER BY id",
        ),
        (
            "challenges",
            "SELECT id,space,policy,credential,record,expires,intent FROM challenges WHERE space=?1 ORDER BY id",
        ),
        (
            "tombstones",
            "SELECT space,credential,identity FROM tombstones WHERE space=?1 ORDER BY credential",
        ),
    ] {
        hash.update([0]);
        hash.update((table.len() as u64).to_be_bytes());
        hash.update(table.as_bytes());
        let mut statement = db.prepare(query)?;
        let columns = statement.column_count();
        let mut rows = statement.query([space.to_string()])?;
        while let Some(row) = rows.next()? {
            hash.update([1]);
            for column in 0..columns {
                match row.get_ref(column)? {
                    ValueRef::Null => hash.update([0]),
                    ValueRef::Integer(value) => {
                        hash.update([1]);
                        hash.update(value.to_be_bytes());
                    }
                    ValueRef::Text(value) => {
                        hash.update([2]);
                        hash.update((value.len() as u64).to_be_bytes());
                        hash.update(value);
                    }
                    _ => return Err(Error::RecoveryRequired),
                }
            }
        }
        hash.update([2]);
    }
    Ok(record::encode_hex(&hash.finalize()))
}

/// Validate the materialized snapshot before using it to issue a new signature.
pub(crate) fn verify_materialized_space(
    db: &Connection,
    space: SpaceId,
    pin: &WitnessPin,
) -> Result<Receipt> {
    let (sequence, id, encoded): (i64, String, String) = db.query_row(
        "SELECT sequence,record_id,receipt FROM events WHERE space=?1 ORDER BY sequence DESC LIMIT 1",
        [space.to_string()], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))
    ).optional()?.ok_or(Error::RecoveryRequired)?;
    let signed = decode(&encoded)?;
    signed.verify_signature(&pin.key()?)?;
    let receipt: Receipt = signed.decode()?;
    if receipt.v != 1
        || receipt.kind != "witness.receipt"
        || receipt.audience != pin.url
        || receipt.space_id != space
        || receipt.witness_key_generation != pin.key_generation
        || sequence < 1
        || receipt.sequence != sequence as u64
        || id != signed.id().to_string()
        || receipt.state_digest != state_digest(db, space)?
    {
        return Err(Error::RecoveryRequired);
    }
    Ok(receipt)
}

fn verify_materialized(db: &Connection, pin: &WitnessPin) -> Result<()> {
    // Include orphaned state and receipts: deleting a Space or injecting rows
    // cannot make it disappear from this integrity check.
    let mut statement = db.prepare("SELECT space FROM spaces UNION SELECT space FROM policies UNION SELECT space FROM challenges UNION SELECT space FROM tombstones UNION SELECT space FROM events")?;
    let spaces = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if spaces.len() > 128 {
        return Err(Error::RecoveryRequired);
    }
    for space in spaces {
        verify_materialized_space(db, space.parse().map_err(|_| Error::RecoveryRequired)?, pin)?;
    }
    Ok(())
}

pub(crate) fn replay(db: &Connection, request: RecordId) -> Result<Option<Response>> {
    db.query_row(
        "SELECT response FROM events WHERE request_id=?1",
        [request.to_string()],
        |r| r.get::<_, String>(0),
    )
    .optional()?
    .map(|s| serde_json::from_str(&s).map_err(|_| Error::Unavailable))
    .transpose()
}

pub(crate) struct Event<'a> {
    pub request: RecordId,
    pub space: SpaceId,
    pub head: RecordId,
    pub name: &'a str,
    pub now: u64,
}

pub(crate) fn append(
    tx: &Transaction<'_>,
    key: &SigningKey,
    pin: &WitnessPin,
    event: Event<'_>,
    mut response: Response,
) -> Result<Response> {
    let tip = position(tx)?;
    if tip.sequence >= MAX_EVENTS {
        return Err(Error::Limit);
    }
    let body = Receipt {
        v: 1,
        kind: "witness.receipt".into(),
        audience: pin.url.clone(),
        sequence: tip.sequence + 1,
        previous: tip.record_id,
        request_id: event.request,
        space_id: event.space,
        authority_head: event.head,
        accepted_at_ms: event.now,
        event: event.name.into(),
        witness_key_generation: pin.key_generation,
        state_digest: state_digest(tx, event.space)?,
    };
    let record = SignedRecord::sign(&serde_json::to_vec(&body).map_err(|_| Error::Invalid)?, key)?;
    let encoded = STANDARD.encode(record.bytes());
    response.receipt = Some(encoded.clone());
    tx.execute("INSERT INTO events(sequence,record_id,receipt,request_id,response,space) VALUES(?1,?2,?3,?4,?5,?6)",
        params![body.sequence as i64,record.id().to_string(),encoded,event.request.to_string(),serde_json::to_string(&response).map_err(|_| Error::Invalid)?,event.space.to_string()])?;
    Ok(response)
}

pub(crate) fn decode(encoded: &str) -> Result<SignedRecord> {
    if encoded.len() > record::MAX_RECORD * 2 {
        return Err(Error::Invalid);
    }
    SignedRecord::parse(&STANDARD.decode(encoded).map_err(|_| Error::Invalid)?).map_err(Into::into)
}

fn private_directory(path: &Path) -> Result<()> {
    if !path.exists() {
        std::fs::create_dir_all(path).map_err(|_| Error::Unavailable)?;
    }
    let meta = std::fs::symlink_metadata(path).map_err(|_| Error::Unavailable)?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return Err(Error::Invalid);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| Error::Unavailable)?;
    }
    Ok(())
}

fn private_file(path: &Path) -> Result<File> {
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if !meta.is_file() || meta.file_type().is_symlink() {
            return Err(Error::Invalid);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if meta.permissions().mode() & 0o777 != 0o600 {
                return Err(Error::Invalid);
            }
        }
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).map_err(|_| Error::Unavailable)
}

#[cfg(test)]
mod tests;
