use crate::{Error, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use elo_core::{
    attachments::{
        MAX_ATTACHMENT_FILE_SIZE, MAX_SPACE_ATTACHMENT_STORAGE,
        broker::{self, Command, Operation, ProviderConfig, Request, Response, StorageStatus},
    },
    authority::{Authority, WitnessPin},
    ids::{AttachmentObjectId, RecordId, SpaceId, StreamId},
    record::{self, SignedRecord},
    witness::{Position, VerifiedFreshness},
};
use fs2::FileExt;
use hmac::{Hmac, Mac};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use std::{
    net::IpAddr,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

pub struct Verified {
    pub command: Command,
    pub authority: Authority,
    pub request_id: RecordId,
}
impl Verified {
    pub fn new(request: Request, audience: &str, now: u64, pin: &WitnessPin) -> Result<Self> {
        Self::verify(request, audience, now, Some(pin))
    }
    #[cfg(test)]
    pub(crate) fn new_test(request: Request, audience: &str, now: u64) -> Result<Self> {
        Self::verify(request, audience, now, None)
    }
    fn verify(
        request: Request,
        audience: &str,
        now: u64,
        pin: Option<&WitnessPin>,
    ) -> Result<Self> {
        if request.command.len() > record::MAX_RECORD * 2 {
            return Err(Error::Invalid);
        }
        let bytes = Zeroizing::new(
            STANDARD
                .decode(&request.command)
                .map_err(|_| Error::Invalid)?,
        );
        let signed = SignedRecord::parse(&bytes)?;
        let command: Command = signed.decode()?;
        // Cheap device authorship precedes verification of the full chain.
        let credential = request.proof.credential(command.credential_id)?;
        signed.verify_signature(credential.key())?;
        let authority = match pin {
            Some(pin) => {
                request
                    .proof
                    .verify_witnessed(command.space_id, command.stream_id, pin)?
            }
            None => request.proof.verify(command.space_id, command.stream_id)?,
        };
        let command = broker::verify_command(&authority, &signed, audience, now)?;
        Ok(Self {
            command,
            authority,
            request_id: signed.id(),
        })
    }
}

#[derive(Clone)]
pub struct Object {
    pub space: String,
    pub object: String,
    pub revision: u64,
    pub creator: String,
    pub size: u64,
    pub hash: String,
    pub expires: u64,
    pub state: String,
}

pub struct Engine {
    db: Connection,
    _lock: std::fs::File,
    key: Zeroizing<[u8; 32]>,
    pub data: PathBuf,
    audience: String,
    max_spaces: usize,
}
impl Engine {
    pub fn open(data: &Path, key_path: &Path, audience: String, max_spaces: usize) -> Result<Self> {
        if max_spaces == 0 || max_spaces > 128 {
            return Err(Error::Invalid);
        }
        private_dir(data)?;
        let canonical_data = std::fs::canonicalize(data).map_err(|_| Error::Unavailable)?;
        let canonical_key = std::fs::canonicalize(key_path).map_err(|_| Error::Unavailable)?;
        if canonical_key.starts_with(canonical_data) {
            return Err(Error::Invalid);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if std::fs::symlink_metadata(key_path)
                .map_err(|_| Error::Unavailable)?
                .permissions()
                .mode()
                & 0o777
                != 0o600
            {
                return Err(Error::Invalid);
            }
        }
        let key = Zeroizing::new(
            elo_core::vault::read_private(key_path).map_err(|_| Error::Unavailable)?,
        );
        let key: [u8; 32] = key.as_slice().try_into().map_err(|_| Error::Invalid)?;
        let lock_path = data.join("broker.lock");
        for path in [&lock_path, &data.join("storage.sqlite")] {
            if path.exists()
                && (!std::fs::symlink_metadata(path)
                    .map_err(|_| Error::Unavailable)?
                    .is_file()
                    || std::fs::symlink_metadata(path)
                        .map_err(|_| Error::Unavailable)?
                        .file_type()
                        .is_symlink())
            {
                return Err(Error::Invalid);
            }
        }
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = options.open(lock_path).map_err(|_| Error::Unavailable)?;
        lock.try_lock_exclusive().map_err(|_| Error::Unavailable)?;
        let db_path = data.join("storage.sqlite");
        options.open(&db_path).map_err(|_| Error::Unavailable)?;
        let db = Connection::open(db_path)?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;
          CREATE TABLE IF NOT EXISTS heads(space TEXT PRIMARY KEY, stream TEXT NOT NULL, head TEXT NOT NULL, sequence INTEGER NOT NULL);
          CREATE TABLE IF NOT EXISTS settings(space TEXT PRIMARY KEY, revision INTEGER NOT NULL, provider TEXT, enabled INTEGER NOT NULL, provider_revision INTEGER NOT NULL, retention_hours INTEGER CHECK(retention_hours IN(1,12,24)));
          CREATE TABLE IF NOT EXISTS providers(space TEXT NOT NULL, revision INTEGER NOT NULL, secret BLOB NOT NULL, PRIMARY KEY(space,revision));
          CREATE TABLE IF NOT EXISTS objects(space TEXT NOT NULL, object TEXT NOT NULL, revision INTEGER NOT NULL, creator TEXT NOT NULL, size INTEGER NOT NULL, hash TEXT NOT NULL, expires INTEGER NOT NULL, state TEXT NOT NULL, busy_until INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(space,object));
          CREATE TABLE IF NOT EXISTS tokens(hash TEXT PRIMARY KEY, space TEXT NOT NULL, object TEXT NOT NULL, head TEXT NOT NULL, action TEXT NOT NULL, expires INTEGER NOT NULL);
          CREATE TABLE IF NOT EXISTS receipts(credential TEXT NOT NULL, nonce TEXT NOT NULL, request TEXT NOT NULL, response TEXT NOT NULL, expires INTEGER NOT NULL, created INTEGER NOT NULL, PRIMARY KEY(credential,nonce));
          CREATE TABLE IF NOT EXISTS registrations(ip TEXT NOT NULL, day INTEGER NOT NULL, count INTEGER NOT NULL, PRIMARY KEY(ip,day));
          CREATE TABLE IF NOT EXISTS witness_floor(singleton INTEGER PRIMARY KEY CHECK(singleton=1), pin TEXT NOT NULL, sequence INTEGER NOT NULL, record TEXT);
          CREATE INDEX IF NOT EXISTS object_expiry ON objects(expires);
          UPDATE objects SET state='deleting' WHERE state='uploading';")?;
        // Existing staging configurations have no owner-signed policy. Keep
        // their provider generation, but reject new reservations until an owner
        // signs Policy or Configure. Existing object deadlines are untouched.
        let columns = db
            .prepare("PRAGMA table_info(settings)")?
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let mut migration = String::from("BEGIN IMMEDIATE;");
        if !columns.iter().any(|column| column == "provider_revision") {
            migration.push_str("ALTER TABLE settings ADD COLUMN provider_revision INTEGER; UPDATE settings SET provider_revision=coalesce((SELECT max(revision) FROM providers WHERE providers.space=settings.space),revision);");
        }
        if !columns.iter().any(|column| column == "retention_hours") {
            migration.push_str("ALTER TABLE settings ADD COLUMN retention_hours INTEGER CHECK(retention_hours IN(1,12,24));");
        }
        migration.push_str("COMMIT;");
        db.execute_batch(&migration)?;
        Ok(Self {
            db,
            _lock: lock,
            key: Zeroizing::new(key),
            data: data.to_owned(),
            audience,
            max_spaces,
        })
    }

    /// The witness journal position is global, so one durable floor also fences
    /// rollback across Spaces. A new operator pin requires an explicit migration.
    pub fn pin_witness(&self, pin: &WitnessPin) -> Result<()> {
        pin.validate()?;
        let pin = serde_json::to_string(pin).map_err(|_| Error::Invalid)?;
        let existing: Option<String> = self
            .db
            .query_row(
                "SELECT pin FROM witness_floor WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        match existing {
            Some(existing) if existing != pin => return Err(Error::Conflict),
            Some(_) => {}
            None => {
                self.db.execute(
                    "INSERT INTO witness_floor(singleton,pin,sequence,record) VALUES(1,?1,0,NULL)",
                    [pin],
                )?;
            }
        }
        Ok(())
    }

    pub fn witness_position(&self) -> Result<Option<Position>> {
        self.db
            .query_row(
                "SELECT sequence,record FROM witness_floor WHERE singleton=1 AND sequence>0",
                [],
                |row| {
                    let record: Option<String> = row.get(1)?;
                    Ok((unsigned(row, 0)?, record))
                },
            )
            .optional()?
            .map(|(sequence, record)| {
                Ok(Position {
                    sequence,
                    record_id: Some(
                        record
                            .ok_or(Error::Unavailable)?
                            .parse()
                            .map_err(|_| Error::Unavailable)?,
                    ),
                })
            })
            .transpose()
    }

    pub fn check_witness(&self, fresh: &VerifiedFreshness, now_ms: u64) -> Result<()> {
        let position = &fresh.body().position;
        if !fresh.is_valid(now_ms)
            || self.witness_position()?.is_some_and(|floor| {
                position.sequence < floor.sequence
                    || (position.sequence == floor.sequence
                        && position.record_id != floor.record_id)
            })
        {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }

    pub fn observe_witness(&self, fresh: &VerifiedFreshness, now_ms: u64) -> Result<()> {
        self.check_witness(fresh, now_ms)?;
        let position = &fresh.body().position;
        if self.db.execute(
            "UPDATE witness_floor SET sequence=?1,record=?2 WHERE singleton=1",
            params![
                integer(position.sequence)?,
                position.record_id.ok_or(Error::Unauthorized)?.to_string()
            ],
        )? != 1
        {
            return Err(Error::Unavailable);
        }
        Ok(())
    }

    /// No proof can bootstrap an existing Space's pin through another stream.
    pub fn authorize(&self, verified: &Verified, now: u64) -> Result<()> {
        let c = &verified.command;
        if c.expires_at <= now {
            return Err(Error::Unauthorized);
        }
        let old = self
            .db
            .query_row(
                "SELECT stream,head,sequence FROM heads WHERE space=?1",
                [c.space_id.to_string()],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        unsigned(r, 2)?,
                    ))
                },
            )
            .optional()?;
        match old {
            Some((stream, head, sequence)) => {
                let head: RecordId = head.parse().map_err(|_| Error::Unavailable)?;
                if stream != c.stream_id.to_string()
                    || (c.config_id != head && !verified.authority.proves_config_at(head, sequence))
                {
                    return Err(Error::Unauthorized);
                }
            }
            None if matches!(c.operation, Operation::Status) => {}
            None if matches!(
                c.operation,
                Operation::Configure {
                    expected_revision: 0,
                    ..
                } | Operation::ConfigureManaged {
                    expected_revision: 0,
                    ..
                }
            ) =>
            {
                if self
                    .db
                    .query_row("SELECT count(*) FROM heads", [], |r| unsigned(r, 0))?
                    >= self.max_spaces as u64
                {
                    return Err(Error::Limit);
                }
            }
            None => return Err(Error::NotConfigured),
        }
        if matches!(
            c.operation,
            Operation::Configure { .. }
                | Operation::ConfigureManaged { .. }
                | Operation::Policy { .. }
                | Operation::Disable { .. }
        ) && !verified.authority.can_manage(c.credential_id)
        {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }

    pub fn replay(&self, verified: &Verified) -> Result<Option<Response>> {
        let c = &verified.command;
        let previous = self
            .db
            .query_row(
                "SELECT request,response FROM receipts WHERE credential=?1 AND nonce=?2",
                params![c.credential_id.to_string(), c.nonce],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
            )
            .optional()?;
        match previous {
            Some((request, response)) if request == verified.request_id.to_string() => {
                let mut response: Response =
                    serde_json::from_str(&response).map_err(|_| Error::Unavailable)?;
                if let Response::Transfer { token, .. } = &mut response {
                    *token = self.token(verified.request_id)?;
                }
                Ok(Some(response))
            }
            Some(_) => Err(Error::Unauthorized),
            None => Ok(None),
        }
    }

    pub fn preflight(&self, verified: &Verified, ip: IpAddr, now: u64) -> Result<Option<Response>> {
        self.authorize(verified, now)?;
        verified.command.operation.validate(now)?;
        if let Some(response) = self.replay(verified)? {
            return Ok(Some(response));
        }
        let c = &verified.command;
        let recent: u64 = self.db.query_row(
            "SELECT count(*) FROM receipts WHERE credential=?1 AND created>?2",
            params![
                c.credential_id.to_string(),
                integer(now.saturating_sub(60))?
            ],
            |r| unsigned(r, 0),
        )?;
        if recent >= 60 {
            return Err(Error::Limit);
        }
        if let Operation::Configure {
            expected_revision, ..
        }
        | Operation::ConfigureManaged {
            expected_revision, ..
        }
        | Operation::Policy {
            expected_revision, ..
        }
        | Operation::Disable { expected_revision } = &c.operation
        {
            let status = self.status(c.space_id)?;
            if status.revision != *expected_revision {
                return Err(Error::Conflict);
            }
            if *expected_revision == 0
                && matches!(
                    c.operation,
                    Operation::Configure { .. } | Operation::ConfigureManaged { .. }
                )
            {
                let ip = ip_hash(ip);
                let count: u64 = self.db.query_row(
                    "SELECT coalesce(sum(count),0) FROM registrations WHERE day=?1 AND ip=?2",
                    params![integer(now / 86400)?, ip],
                    |r| unsigned(r, 0),
                )?;
                let all: u64 = self.db.query_row(
                    "SELECT coalesce(sum(count),0) FROM registrations WHERE day=?1",
                    [integer(now / 86400)?],
                    |r| unsigned(r, 0),
                )?;
                if count >= 4 || all >= 32 {
                    return Err(Error::Limit);
                }
            }
        }
        Ok(None)
    }

    pub fn status(&self, space: SpaceId) -> Result<StorageStatus> {
        status_from(&self.db, &space.to_string())
    }

    pub fn apply(&mut self, verified: &Verified, ip: IpAddr, now: u64) -> Result<Response> {
        self.apply_with_managed(verified, ip, now, None)
    }

    /// The provider is supplied by trusted server configuration, never the API
    /// or a renderer. Authorization and replay retain the original signed command.
    pub(crate) fn apply_with_managed(
        &mut self,
        verified: &Verified,
        ip: IpAddr,
        now: u64,
        managed: Option<&ProviderConfig>,
    ) -> Result<Response> {
        if let Some(response) = self.preflight(verified, ip, now)? {
            return Ok(response);
        }
        let c = &verified.command;
        let space = c.space_id.to_string();
        let configuration = match &c.operation {
            Operation::Configure {
                expected_revision,
                provider,
                retention_hours,
            } => Some((*expected_revision, provider, *retention_hours)),
            Operation::ConfigureManaged {
                expected_revision,
                retention_hours,
            } => Some((
                *expected_revision,
                managed.ok_or(Error::Unauthorized)?,
                *retention_hours,
            )),
            _ => None,
        };
        if let Some((_, provider, _)) = configuration {
            provider.validate()?;
        }
        let secret = configuration
            .map(|(revision, provider, _)| self.seal(&space, revision + 1, provider))
            .transpose()?;
        let token = self.token(verified.request_id)?;
        let token_hash = hash(&token);
        let audience = self.audience.clone();
        let tx = self.db.transaction()?;
        let response = match &c.operation {
            Operation::Status => Response::Status {
                status: status_from(&tx, &space)?,
            },
            Operation::Configure { .. } | Operation::ConfigureManaged { .. } => {
                let (expected_revision, provider, retention_hours) =
                    configuration.ok_or(Error::Invalid)?;
                let revision = expected_revision + 1;
                let count: u64 = tx.query_row(
                    "SELECT count(*) FROM providers WHERE space=?1",
                    [&space],
                    |r| unsigned(r, 0),
                )?;
                if count >= 32 {
                    return Err(Error::Limit);
                }
                tx.execute(
                    "INSERT INTO providers(space,revision,secret) VALUES(?1,?2,?3)",
                    params![space, integer(revision)?, secret],
                )?;
                tx.execute("INSERT INTO settings(space,revision,provider,enabled,provider_revision,retention_hours) VALUES(?1,?2,?3,1,?2,?4) ON CONFLICT(space) DO UPDATE SET revision=excluded.revision,provider=excluded.provider,enabled=1,provider_revision=excluded.provider_revision,retention_hours=excluded.retention_hours",params![space,integer(revision)?,provider.name(),retention_hours])?;
                if expected_revision == 0 {
                    tx.execute("INSERT INTO registrations(ip,day,count) VALUES(?1,?2,1) ON CONFLICT(ip,day) DO UPDATE SET count=count+1",params![ip_hash(ip),integer(now/86400)?])?;
                }
                Response::Status {
                    status: status_from(&tx, &space)?,
                }
            }
            Operation::Policy {
                expected_revision,
                retention_hours,
            } => {
                if *expected_revision == 0 {
                    return Err(Error::NotConfigured);
                }
                tx.execute(
                    "UPDATE settings SET revision=revision+1,retention_hours=?2 WHERE space=?1",
                    params![space, retention_hours],
                )?;
                Response::Status {
                    status: status_from(&tx, &space)?,
                }
            }
            Operation::Disable { expected_revision } => {
                if *expected_revision == 0 {
                    return Err(Error::NotConfigured);
                }
                tx.execute(
                    "UPDATE settings SET revision=revision+1,enabled=0 WHERE space=?1",
                    [&space],
                )?;
                tx.execute(
                    "DELETE FROM tokens WHERE space=?1 AND action='upload'",
                    [&space],
                )?;
                Response::Status {
                    status: status_from(&tx, &space)?,
                }
            }
            Operation::Reserve {
                object_id,
                encrypted_size,
                ciphertext_sha256,
            } => {
                let (revision,retention_hours)=tx.query_row("SELECT provider_revision,retention_hours FROM settings WHERE space=?1 AND enabled=1 AND retention_hours IN(1,12,24)",[&space],|row|Ok((unsigned(row,0)?,unsigned(row,1)?))).optional()?.ok_or(Error::NotConfigured)?;
                let expires_at_ms = now
                    .checked_add(retention_hours.checked_mul(3600).ok_or(Error::Invalid)?)
                    .and_then(|seconds| seconds.checked_mul(1000))
                    .filter(|ms| *ms <= record::MAX_EXPIRY_TIMESTAMP_MS)
                    .ok_or(Error::Invalid)?;
                let used: u64 = tx.query_row(
                    "SELECT coalesce(sum(size),0) FROM objects WHERE space=?1",
                    [&space],
                    |r| unsigned(r, 0),
                )?;
                let count: u64 = tx.query_row(
                    "SELECT count(*) FROM objects WHERE space=?1",
                    [&space],
                    |r| unsigned(r, 0),
                )?;
                if used.saturating_add(*encrypted_size) > MAX_SPACE_ATTACHMENT_STORAGE
                    || count >= 1024
                {
                    return Err(Error::Limit);
                }
                let exists: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM objects WHERE space=?1 AND object=?2)",
                    params![space, object_id.to_string()],
                    |r| r.get(0),
                )?;
                if exists {
                    return Err(Error::Conflict);
                }
                tx.execute("INSERT INTO objects(space,object,revision,creator,size,hash,expires,state) VALUES(?1,?2,?3,?4,?5,?6,?7,'pending')",params![space,object_id.to_string(),integer(revision)?,c.credential_id.to_string(),integer(*encrypted_size)?,ciphertext_sha256,integer(expires_at_ms)?])?;
                let expires = now
                    .saturating_add(broker::TRANSFER_TTL)
                    .min(expires_at_ms / 1000);
                tx.execute("INSERT INTO tokens(hash,space,object,head,action,expires) VALUES(?1,?2,?3,?4,'upload',?5)",params![token_hash,space,object_id.to_string(),c.config_id.to_string(),integer(expires)?])?;
                Response::Transfer {
                    object_id: *object_id,
                    url: format!("{audience}/objects/{object_id}"),
                    token: token.clone(),
                    expires_at: expires,
                    object_expires_at_ms: expires_at_ms,
                }
            }
            Operation::Complete { object_id } => {
                let object = read_object(&tx, &space, &object_id.to_string())?;
                if object.creator != c.credential_id.to_string() || object.expires <= now * 1000 {
                    return Err(Error::Unauthorized);
                }
                if object.state != "uploaded" && object.state != "complete" {
                    return Err(Error::Conflict);
                }
                tx.execute(
                    "UPDATE objects SET state='complete' WHERE space=?1 AND object=?2",
                    params![space, object_id.to_string()],
                )?;
                Response::Complete {
                    object_id: *object_id,
                }
            }
            Operation::Download { object_id } => {
                let object = read_object(&tx, &space, &object_id.to_string())?;
                if object.state != "complete" || object.expires <= now * 1000 {
                    return Err(Error::Missing);
                }
                let expires = now
                    .saturating_add(broker::TRANSFER_TTL)
                    .min(object.expires / 1000);
                tx.execute("INSERT INTO tokens(hash,space,object,head,action,expires) VALUES(?1,?2,?3,?4,'download',?5)",params![token_hash,space,object_id.to_string(),c.config_id.to_string(),integer(expires)?])?;
                Response::Transfer {
                    object_id: *object_id,
                    url: format!("{audience}/objects/{object_id}"),
                    token: token.clone(),
                    expires_at: expires,
                    object_expires_at_ms: object.expires,
                }
            }
            Operation::Cancel { object_id } => {
                let object = read_object(&tx, &space, &object_id.to_string())?;
                if object.creator != c.credential_id.to_string()
                    && !verified.authority.can_manage(c.credential_id)
                {
                    return Err(Error::Unauthorized);
                }
                if object.state == "uploading" || object.state == "complete" {
                    return Err(Error::Conflict);
                }
                tx.execute(
                    "UPDATE objects SET state='deleting' WHERE space=?1 AND object=?2",
                    params![space, object_id.to_string()],
                )?;
                tx.execute(
                    "DELETE FROM tokens WHERE space=?1 AND object=?2",
                    params![space, object_id.to_string()],
                )?;
                Response::Cancelled {
                    object_id: *object_id,
                }
            }
        };
        // A denied operation rolls back before it can advance the durable fence.
        // Read-only status cannot register an arbitrary Space or stream.
        let known: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM heads WHERE space=?1)",
            [&space],
            |r| r.get(0),
        )?;
        if known
            || matches!(
                c.operation,
                Operation::Configure { .. } | Operation::ConfigureManaged { .. }
            )
        {
            tx.execute("INSERT INTO heads(space,stream,head,sequence) VALUES(?1,?2,?3,?4) ON CONFLICT(space) DO UPDATE SET head=excluded.head,sequence=excluded.sequence",params![space,c.stream_id.to_string(),c.config_id.to_string(),integer(verified.authority.head()?.sequence)?])?;
        }
        let mut saved = response.clone();
        if let Response::Transfer { token, .. } = &mut saved {
            token.clear();
        }
        tx.execute("INSERT INTO receipts(credential,nonce,request,response,expires,created) VALUES(?1,?2,?3,?4,?5,?6)",params![c.credential_id.to_string(),c.nonce,verified.request_id.to_string(),serde_json::to_string(&saved).map_err(|_|Error::Unavailable)?,integer(c.expires_at)?,integer(now)?])?;
        tx.commit()?;
        Ok(response)
    }

    fn token(&self, request: RecordId) -> Result<String> {
        let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(self.key.as_ref())
            .map_err(|_| Error::Unavailable)?;
        mac.update(b"elo.now/storage-transfer/v1\0");
        mac.update(request.as_bytes());
        Ok(record::encode_hex(&mac.finalize().into_bytes()))
    }
    fn seal(&self, space: &str, revision: u64, provider: &ProviderConfig) -> Result<Vec<u8>> {
        let plain = Zeroizing::new(serde_json::to_vec(provider).map_err(|_| Error::Invalid)?);
        let mut nonce = [0; 24];
        getrandom::fill(&mut nonce).map_err(|_| Error::Unavailable)?;
        let cipher =
            XChaCha20Poly1305::new_from_slice(self.key.as_ref()).map_err(|_| Error::Unavailable)?;
        let aad = format!("elo.now/storage-secret/v1/{space}/{revision}");
        let mut result = nonce.to_vec();
        result.extend(
            cipher
                .encrypt(
                    &XNonce::from(nonce),
                    Payload {
                        msg: &plain,
                        aad: aad.as_bytes(),
                    },
                )
                .map_err(|_| Error::Unavailable)?,
        );
        Ok(result)
    }
    pub fn provider(&self, space: &str, revision: u64) -> Result<ProviderConfig> {
        let secret: Vec<u8> = self.db.query_row(
            "SELECT secret FROM providers WHERE space=?1 AND revision=?2",
            params![space, integer(revision)?],
            |r| r.get(0),
        )?;
        if secret.len() < 40 {
            return Err(Error::Unavailable);
        }
        let cipher =
            XChaCha20Poly1305::new_from_slice(self.key.as_ref()).map_err(|_| Error::Unavailable)?;
        let aad = format!("elo.now/storage-secret/v1/{space}/{revision}");
        let plain = Zeroizing::new(
            cipher
                .decrypt(
                    &XNonce::try_from(&secret[..24]).map_err(|_| Error::Unavailable)?,
                    Payload {
                        msg: &secret[24..],
                        aad: aad.as_bytes(),
                    },
                )
                .map_err(|_| Error::Unavailable)?,
        );
        serde_json::from_slice(&plain).map_err(|_| Error::Unavailable)
    }
    pub fn claim(
        &mut self,
        object: AttachmentObjectId,
        token: &str,
        action: &str,
        now: u64,
    ) -> Result<Object> {
        self.token_target(object, token, action, now)?;
        let tx = self.db.transaction()?;
        let space=tx.query_row("SELECT t.space FROM tokens t JOIN heads h ON h.space=t.space AND h.head=t.head WHERE t.hash=?1 AND t.object=?2 AND t.action=?3 AND t.expires>?4",params![hash(token),object.to_string(),action,integer(now)?],|r|r.get::<_,String>(0)).optional()?.ok_or(Error::Unauthorized)?;
        let row = read_object(&tx, &space, &object.to_string())?;
        if row.expires <= now * 1000
            || (action == "upload" && row.state != "pending")
            || (action == "download" && row.state != "complete")
        {
            return Err(Error::Missing);
        }
        if action == "upload" {
            tx.execute(
                "UPDATE objects SET state='uploading',busy_until=?3 WHERE space=?1 AND object=?2",
                params![space, object.to_string(), integer(now.saturating_add(100))?],
            )?;
        }
        tx.execute("DELETE FROM tokens WHERE hash=?1", [hash(token)])?;
        tx.commit()?;
        Ok(row)
    }

    /// Read the exact token scope before contacting the witness. The caller
    /// rechecks this tuple under the engine lock before consuming the token.
    pub fn token_target(
        &self,
        object: AttachmentObjectId,
        token: &str,
        action: &str,
        now: u64,
    ) -> Result<(SpaceId, StreamId, RecordId)> {
        if token.len() != 64
            || !token
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::Unauthorized);
        }
        let (space,stream,head)=self.db.query_row("SELECT t.space,h.stream,t.head FROM tokens t JOIN heads h ON h.space=t.space AND h.head=t.head WHERE t.hash=?1 AND t.object=?2 AND t.action=?3 AND t.expires>?4",params![hash(token),object.to_string(),action,integer(now)?],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?))).optional()?.ok_or(Error::Unauthorized)?;
        Ok((
            space.parse().map_err(|_| Error::Unavailable)?,
            stream.parse().map_err(|_| Error::Unavailable)?,
            head.parse().map_err(|_| Error::Unavailable)?,
        ))
    }
    pub fn uploaded(&self, object: &Object, success: bool) -> Result<()> {
        self.db.execute(
            "UPDATE objects SET state=?3,busy_until=CASE WHEN ?3='uploaded' THEN 0 ELSE busy_until END WHERE space=?1 AND object=?2 AND state='uploading'",
            params![
                object.space,
                object.object,
                if success { "uploaded" } else { "deleting" }
            ],
        )?;
        Ok(())
    }
    pub fn garbage(&self, now: u64) -> Result<Vec<Object>> {
        let mut statement=self.db.prepare("SELECT space,object,revision,creator,size,hash,expires,state FROM objects WHERE state!='uploading' AND busy_until<=?2 AND (state='deleting' OR expires<=?1) LIMIT 32")?;
        Ok(statement
            .query_map(
                params![integer(now.saturating_mul(1000))?, integer(now)?],
                object_row,
            )?
            .collect::<std::result::Result<Vec<_>, _>>()?)
    }
    pub fn deleted(&self, object: &Object) -> Result<()> {
        self.db.execute(
            "DELETE FROM tokens WHERE space=?1 AND object=?2",
            params![object.space, object.object],
        )?;
        self.db.execute(
            "DELETE FROM objects WHERE space=?1 AND object=?2 AND state!='uploading'",
            params![object.space, object.object],
        )?;
        Ok(())
    }
    pub fn prune(&self, now: u64) -> Result<()> {
        self.db.execute(
            "DELETE FROM receipts WHERE expires<?1",
            [integer(now.saturating_sub(60))?],
        )?;
        self.db
            .execute("DELETE FROM tokens WHERE expires<=?1", [integer(now)?])?;
        self.db.execute(
            "DELETE FROM registrations WHERE day<?1",
            [integer(now / 86400)?],
        )?;
        self.db.execute("DELETE FROM providers WHERE NOT EXISTS(SELECT 1 FROM objects o WHERE o.space=providers.space AND o.revision=providers.revision) AND NOT EXISTS(SELECT 1 FROM settings s WHERE s.space=providers.space AND s.provider_revision=providers.revision AND s.enabled=1)",[])?;
        Ok(())
    }
}
fn status_from(db: &Connection, space: &str) -> Result<StorageStatus> {
    let (revision, provider, enabled, retention_hours) = db
        .query_row(
            "SELECT revision,provider,enabled,retention_hours FROM settings WHERE space=?1",
            [space],
            |row| {
                Ok((
                    unsigned(row, 0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, bool>(2)?,
                    row.get::<_, Option<u32>>(3)?,
                ))
            },
        )
        .optional()?
        .unwrap_or((0, None, false, None));
    let used_bytes = db.query_row(
        "SELECT coalesce(sum(size),0) FROM objects WHERE space=?1",
        [space],
        |r| unsigned(r, 0),
    )?;
    Ok(StorageStatus {
        configured: provider.is_some(),
        enabled: enabled && retention_hours.is_some(),
        provider,
        revision,
        used_bytes,
        max_space_bytes: MAX_SPACE_ATTACHMENT_STORAGE,
        max_file_bytes: MAX_ATTACHMENT_FILE_SIZE,
        retention_hours,
    })
}

fn read_object(db: &Connection, space: &str, object: &str) -> Result<Object> {
    db.query_row("SELECT space,object,revision,creator,size,hash,expires,state FROM objects WHERE space=?1 AND object=?2",params![space,object],object_row).optional()?.ok_or(Error::Missing)
}
fn object_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Object> {
    Ok(Object {
        space: r.get(0)?,
        object: r.get(1)?,
        revision: unsigned(r, 2)?,
        creator: r.get(3)?,
        size: unsigned(r, 4)?,
        hash: r.get(5)?,
        expires: unsigned(r, 6)?,
        state: r.get(7)?,
    })
}
fn hash(s: &str) -> String {
    record::encode_hex(&Sha256::digest(s.as_bytes()))
}
fn ip_hash(ip: IpAddr) -> String {
    hash(&format!("elo.now/storage-admission/v1/{ip}"))
}
pub fn private_dir(path: &Path) -> Result<()> {
    if !path.exists() {
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .recursive(true)
            .create(path)
            .map_err(|_| Error::Unavailable)?;
    }
    let metadata = std::fs::symlink_metadata(path).map_err(|_| Error::Unavailable)?;
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
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests;

fn integer(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| Error::Invalid)
}
fn unsigned(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<u64> {
    let value: i64 = row.get(index)?;
    u64::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(index, value))
}
