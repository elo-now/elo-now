//! Ciphertext-only store. A separate DB and process lock, no client vault/API.
use crate::{
    crypto::MAX_CIPHERTEXT,
    identity::generate_signing_key,
    ids::{MailboxId, ObjectId, PeerId},
    record::{MAX_INTEGER, SignedRecord, encode_hex, hex, random_hex},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;
use thiserror::Error;
const MIGRATION: &str = include_str!("../../../migrations/001_replica.sql");
const DELEGATION_MIGRATION: &str =
    include_str!("../../../migrations/002_replica_mailbox_delegation.sql");
pub const MAX_CHILD_MAILBOXES: u64 = 256;
pub const MAX_MAILBOX_LIFETIME_MS: u64 = 37 * 86_400_000;
#[derive(Debug, Error)]
pub enum ReplicaError {
    #[error("mailbox authorization denied")]
    Unauthorized,
    #[error("invalid object, request or receipt")]
    Invalid,
    #[error("mailbox quota exceeded")]
    Quota,
    #[error("object unavailable")]
    NotFound,
    #[error("delivery conflicts with existing immutable data")]
    Conflict,
    #[error("storage unavailable")]
    Storage,
    #[error("replica directory is already open or belongs to a client")]
    Directory,
}
pub type Result<T> = std::result::Result<T, ReplicaError>;
impl From<rusqlite::Error> for ReplicaError {
    fn from(_: rusqlite::Error) -> Self {
        Self::Storage
    }
}
impl From<std::io::Error> for ReplicaError {
    fn from(_: std::io::Error) -> Self {
        Self::Storage
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransferHint {
    Eager,
    Lazy,
}
impl TransferHint {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Eager => "eager",
            Self::Lazy => "lazy",
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxDescriptor {
    pub mailbox_id: MailboxId,
    pub read_token: String,
    pub write_token: String,
}
impl MailboxDescriptor {
    pub fn random() -> Result<Self> {
        let mut r = [0u8; 32];
        let mut w = [0u8; 32];
        getrandom::fill(&mut r).map_err(|_| ReplicaError::Storage)?;
        getrandom::fill(&mut w).map_err(|_| ReplicaError::Storage)?;
        Ok(Self {
            mailbox_id: random_hex::<32>()
                .map_err(|_| ReplicaError::Storage)?
                .parse()
                .map_err(|_| ReplicaError::Invalid)?,
            read_token: URL_SAFE_NO_PAD.encode(r),
            write_token: URL_SAFE_NO_PAD.encode(w),
        })
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChildMailbox {
    pub descriptor: MailboxDescriptor,
    pub quota_bytes: u64,
    pub expires_at: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryEntry {
    pub arrival_seq: u64,
    pub object_id: ObjectId,
    pub size_bytes: u64,
    pub transfer_hint: TransferHint,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inventory {
    pub storage_generation: String,
    pub head: u64,
    pub entries: Vec<InventoryEntry>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptBody {
    pub v: u64,
    pub kind: String,
    pub peer_id: PeerId,
    pub mailbox_id: MailboxId,
    pub object_id: ObjectId,
    pub size_bytes: u64,
    pub arrival_seq: u64,
    pub storage_generation: String,
    pub storage_class: String,
    pub retention: String,
    pub nonce: String,
    pub stored_local_ms: u64,
}
#[derive(Clone, Debug)]
pub struct VerifiedReceipt {
    record: SignedRecord,
    body: ReceiptBody,
}
impl VerifiedReceipt {
    pub fn verify(
        bytes: &[u8],
        key: &VerifyingKey,
        mailbox: MailboxId,
        object: ObjectId,
        size: usize,
    ) -> Result<Self> {
        let r = SignedRecord::parse(bytes).map_err(|_| ReplicaError::Invalid)?;
        r.verify_signature(key).map_err(|_| ReplicaError::Invalid)?;
        let b: ReceiptBody = r.decode().map_err(|_| ReplicaError::Invalid)?;
        if b.v != 1
            || b.kind != "storage.receipt"
            || b.peer_id != peer_id(key)
            || b.mailbox_id != mailbox
            || b.object_id != object
            || b.size_bytes != size as u64
            || b.arrival_seq == 0
            || b.arrival_seq > MAX_INTEGER
            || b.storage_class != "sqlite-wal-full"
            || b.retention != "manual-no-auto-gc"
        {
            return Err(ReplicaError::Invalid);
        }
        hex::<32>(&b.storage_generation).map_err(|_| ReplicaError::Invalid)?;
        hex::<16>(&b.nonce).map_err(|_| ReplicaError::Invalid)?;
        Ok(Self { record: r, body: b })
    }
    pub fn body(&self) -> &ReceiptBody {
        &self.body
    }
    pub fn bytes(&self) -> &[u8] {
        self.record.bytes()
    }
}
pub fn peer_id(key: &VerifyingKey) -> PeerId {
    let mut h = Sha256::new();
    h.update(b"elo.now/peer-id/v1\0");
    h.update(key.as_bytes());
    PeerId::from_bytes(h.finalize().into())
}
struct Db {
    connection: Connection,
    _lock: File,
    key: SigningKey,
    generation: String,
}
#[derive(Clone)]
pub struct ReplicaStore {
    db: Arc<Mutex<Db>>,
    key: VerifyingKey,
}
impl ReplicaStore {
    pub async fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let db = tokio::task::spawn_blocking(move || open_db(path))
            .await
            .map_err(|_| ReplicaError::Storage)??;
        let key = db.key.verifying_key();
        Ok(Self {
            db: Arc::new(Mutex::new(db)),
            key,
        })
    }
    pub fn key(&self) -> &VerifyingKey {
        &self.key
    }
    pub fn peer_id(&self) -> PeerId {
        peer_id(&self.key)
    }
    async fn call<T: Send + 'static>(
        &self,
        op: impl FnOnce(&mut Db) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || {
            let mut guard = db.lock().map_err(|_| ReplicaError::Storage)?;
            op(&mut guard)
        })
        .await
        .map_err(|_| ReplicaError::Storage)?
    }
    pub async fn create_mailbox(&self, quota: u64) -> Result<MailboxDescriptor> {
        if quota == 0 || quota > MAX_INTEGER {
            return Err(ReplicaError::Invalid);
        }
        let descriptor = MailboxDescriptor::random()?;
        let d = descriptor.clone();
        self.call(move |db| {
            db.connection.execute(
                "INSERT INTO mailboxes VALUES(?1,?2,?3,?4)",
                params![
                    d.mailbox_id.to_string(),
                    token_hash(&d.read_token)?,
                    token_hash(&d.write_token)?,
                    quota as i64
                ],
            )?;
            Ok(())
        })
        .await?;
        Ok(descriptor)
    }
    pub async fn authorize(&self, mailbox: MailboxId, token: String, write: bool) -> Result<()> {
        self.call(move |db| authorize(&db.connection, mailbox, &token, write))
            .await
    }
    /// Idempotent allocation using client-generated capabilities saved before upload.
    /// Every descendant shares its ancestors' byte and mailbox-count budgets.
    pub async fn create_child(
        &self,
        parent: MailboxId,
        token: String,
        child: ChildMailbox,
    ) -> Result<()> {
        let read = token_hash(&child.descriptor.read_token)?;
        let write = token_hash(&child.descriptor.write_token)?;
        let time = now()?;
        if read == write
            || child.quota_bytes == 0
            || child.quota_bytes > MAX_INTEGER
            || child.expires_at <= time
            || child.expires_at > time + MAX_MAILBOX_LIFETIME_MS
        {
            return Err(ReplicaError::Invalid);
        }
        self.call(move |db| {
            let tx = db.connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            authorize(&tx, parent, &token, true)?;
            let ancestors = ancestors(&tx, parent)?;
            if ancestors.len() > 2 { return Err(ReplicaError::Invalid); }
            let id = child.descriptor.mailbox_id.to_string();
            type Existing = (String, Vec<u8>, Vec<u8>, i64, i64);
            let existing: Option<Existing> = tx.query_row(
                "SELECT d.parent_id,m.read_token_hash,m.write_token_hash,m.quota_bytes,d.expires_at FROM mailbox_delegations d JOIN mailboxes m USING(mailbox_id) WHERE mailbox_id=?1",
                [&id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional()?;
            if let Some(old) = existing {
                return if old == (parent.to_string(), read, write, child.quota_bytes as i64, child.expires_at as i64) { Ok(()) } else { Err(ReplicaError::Conflict) };
            }
            for ancestor in &ancestors {
                let (quota, expiry): (i64, Option<i64>) = tx.query_row(
                    "SELECT m.quota_bytes,d.expires_at FROM mailboxes m LEFT JOIN mailbox_delegations d USING(mailbox_id) WHERE m.mailbox_id=?1", [ancestor], |r| Ok((r.get(0)?,r.get(1)?)))?;
                if child.quota_bytes > quota as u64 || expiry.is_some_and(|e| child.expires_at > e as u64) { return Err(ReplicaError::Quota); }
                let count: i64 = tx.query_row(
                    "WITH RECURSIVE tree(id) AS (SELECT ?1 UNION ALL SELECT mailbox_id FROM mailbox_delegations JOIN tree ON parent_id=tree.id) SELECT count(*)-1 FROM tree", [ancestor], |r| r.get(0))?;
                if count as u64 >= MAX_CHILD_MAILBOXES { return Err(ReplicaError::Quota); }
            }
            if tx.query_row("SELECT count(*) FROM mailboxes WHERE mailbox_id=?1", [&id], |r| r.get::<_,i64>(0))? != 0 { return Err(ReplicaError::Conflict); }
            tx.execute("INSERT INTO mailboxes VALUES(?1,?2,?3,?4)", params![id,read,write,child.quota_bytes as i64])?;
            tx.execute("INSERT INTO mailbox_delegations VALUES(?1,?2,?3)", params![id,parent.to_string(),child.expires_at as i64])?;
            tx.commit()?;
            Ok(())
        }).await
    }
    pub async fn post(
        &self,
        mailbox: MailboxId,
        token: String,
        id: ObjectId,
        bytes: Vec<u8>,
        hint: TransferHint,
    ) -> Result<(bool, Vec<u8>)> {
        self.call(move|db|{
   authorize(&db.connection,mailbox,&token,true)?;
   if bytes.is_empty()||bytes.len()>MAX_CIPHERTEXT||ObjectId::of_ciphertext(&bytes)!=id{return Err(ReplicaError::Invalid);}
   let time=now()?;let tx=db.connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
   let old:Option<(i64,String)>=tx.query_row("SELECT arrival_seq,transfer_hint FROM deliveries WHERE mailbox_id=?1 AND object_id=?2",params![mailbox.to_string(),id.to_string()],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
   let inserted=old.is_none();
   let seq=if let Some((seq,mode))=old {
    let stored:Vec<u8>=tx.query_row("SELECT ciphertext FROM objects WHERE object_id=?1",[id.to_string()],|r|r.get(0))?;
    if stored!=bytes||mode!=hint.as_str(){return Err(ReplicaError::Conflict);}seq
   }else{
    for ancestor in ancestors(&tx, mailbox)? {
     let quota:i64=tx.query_row("SELECT quota_bytes FROM mailboxes WHERE mailbox_id=?1",[&ancestor],|r|r.get(0))?;
     let used:i64=tx.query_row("WITH RECURSIVE tree(id) AS (SELECT ?1 UNION ALL SELECT mailbox_id FROM mailbox_delegations JOIN tree ON parent_id=tree.id) SELECT coalesce(sum(o.size_bytes),0) FROM deliveries d JOIN objects o USING(object_id) JOIN tree ON d.mailbox_id=tree.id",[&ancestor],|r|r.get(0))?;
     if bytes.len() as i64>quota-used{return Err(ReplicaError::Quota);}
    }
    tx.execute("INSERT INTO objects VALUES(?1,?2,?3,?4) ON CONFLICT(object_id) DO NOTHING",params![id.to_string(),bytes,bytes.len() as i64,time as i64])?;
    let stored:Vec<u8>=tx.query_row("SELECT ciphertext FROM objects WHERE object_id=?1",[id.to_string()],|r|r.get(0))?;if stored!=bytes{return Err(ReplicaError::Conflict);}
    tx.execute("INSERT INTO deliveries(mailbox_id,object_id,transfer_hint) VALUES(?1,?2,?3)",params![mailbox.to_string(),id.to_string(),hint.as_str()])?;tx.last_insert_rowid()
   };
   let stored_time:i64=tx.query_row("SELECT stored_local_ms FROM objects WHERE object_id=?1",[id.to_string()],|r|r.get(0))?;
   tx.commit()?;
   let body=ReceiptBody{v:1,kind:"storage.receipt".into(),peer_id:peer_id(&db.key.verifying_key()),mailbox_id:mailbox,object_id:id,size_bytes:bytes.len() as u64,arrival_seq:seq as u64,storage_generation:db.generation.clone(),storage_class:"sqlite-wal-full".into(),retention:"manual-no-auto-gc".into(),nonce:random_hex::<16>().map_err(|_|ReplicaError::Storage)?,stored_local_ms:stored_time as u64};
   let body=serde_json::to_vec(&body).map_err(|_|ReplicaError::Storage)?;let receipt=SignedRecord::sign(&body,&db.key).map_err(|_|ReplicaError::Storage)?;
   Ok((inserted,receipt.bytes().to_vec()))
  }).await
    }
    pub async fn get(&self, mailbox: MailboxId, token: String, id: ObjectId) -> Result<Vec<u8>> {
        self.call(move|db|{authorize(&db.connection,mailbox,&token,false)?;let bytes:Vec<u8>=db.connection.query_row("SELECT o.ciphertext FROM objects o JOIN deliveries d USING(object_id) WHERE d.mailbox_id=?1 AND d.object_id=?2",params![mailbox.to_string(),id.to_string()],|r|r.get(0)).optional()?.ok_or(ReplicaError::NotFound)?;if ObjectId::of_ciphertext(&bytes)!=id{return Err(ReplicaError::Storage);}Ok(bytes)}).await
    }
    pub async fn inventory(
        &self,
        mailbox: MailboxId,
        token: String,
        after: u64,
        limit: usize,
    ) -> Result<Inventory> {
        if after > MAX_INTEGER || !(1..=128).contains(&limit) {
            return Err(ReplicaError::Invalid);
        }
        self.call(move|db|{
   authorize(&db.connection,mailbox,&token,false)?;
   let head:i64=db.connection.query_row("SELECT coalesce(max(arrival_seq),0) FROM deliveries WHERE mailbox_id=?1",[mailbox.to_string()],|r|r.get(0))?;
   let mut q=db.connection.prepare("SELECT d.arrival_seq,d.object_id,o.size_bytes,d.transfer_hint FROM deliveries d JOIN objects o USING(object_id) WHERE d.mailbox_id=?1 AND d.arrival_seq>?2 ORDER BY d.arrival_seq LIMIT ?3")?;
   let rows=q.query_map(params![mailbox.to_string(),after as i64,limit as i64],|r|Ok((r.get::<_,i64>(0)?,r.get::<_,String>(1)?,r.get::<_,i64>(2)?,r.get::<_,String>(3)?)))?;
   let mut entries=Vec::new();for row in rows{let (arrival,id,size,hint)=row?;entries.push(InventoryEntry{arrival_seq:arrival as u64,object_id:id.parse().map_err(|_|ReplicaError::Storage)?,size_bytes:size as u64,transfer_hint:match hint.as_str(){"eager"=>TransferHint::Eager,"lazy"=>TransferHint::Lazy,_=>return Err(ReplicaError::Storage)}});}
   Ok(Inventory{storage_generation:db.generation.clone(),head:head as u64,entries})
  }).await
    }
}
fn token_hash(token: &str) -> Result<Vec<u8>> {
    let bytes = URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| ReplicaError::Unauthorized)?;
    if bytes.len() != 32 || URL_SAFE_NO_PAD.encode(&bytes) != token {
        return Err(ReplicaError::Unauthorized);
    }
    Ok(Sha256::digest(bytes).to_vec())
}
fn ancestors(c: &Connection, mailbox: MailboxId) -> Result<Vec<String>> {
    let mut q = c.prepare("WITH RECURSIVE chain(id) AS (SELECT ?1 UNION ALL SELECT parent_id FROM mailbox_delegations JOIN chain ON mailbox_id=chain.id) SELECT id FROM chain")?;
    Ok(q.query_map([mailbox.to_string()], |r| r.get(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?)
}
fn authorize(c: &Connection, mailbox: MailboxId, token: &str, write: bool) -> Result<()> {
    let expiry: Option<i64> = c
        .query_row(
            "SELECT expires_at FROM mailbox_delegations WHERE mailbox_id=?1",
            [mailbox.to_string()],
            |r| r.get(0),
        )
        .optional()?;
    if expiry.is_some_and(|e| now().map_or(true, |n| e as u64 <= n)) {
        return Err(ReplicaError::Unauthorized);
    }
    let sql = if write {
        "SELECT write_token_hash FROM mailboxes WHERE mailbox_id=?1"
    } else {
        "SELECT read_token_hash FROM mailboxes WHERE mailbox_id=?1"
    };
    let expected: Option<Vec<u8>> = c
        .query_row(sql, [mailbox.to_string()], |r| r.get(0))
        .optional()?;
    let actual = token_hash(token)?;
    if !bool::from(expected.unwrap_or(vec![0; 32]).ct_eq(&actual)) {
        return Err(ReplicaError::Unauthorized);
    }
    Ok(())
}
fn now() -> Result<u64> {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ReplicaError::Storage)?
        .as_millis();
    if n > MAX_INTEGER as u128 {
        return Err(ReplicaError::Storage);
    }
    Ok(n as u64)
}
fn private_file(path: &Path) -> Result<File> {
    if fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(ReplicaError::Directory);
    }
    let mut o = OpenOptions::new();
    o.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    Ok(o.open(path)?)
}
fn open_db(path: PathBuf) -> Result<Db> {
    if !path.exists() {
        let mut b = fs::DirBuilder::new();
        b.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            b.mode(0o700);
        }
        b.create(&path)?;
    }
    if path.join("client.sqlite").exists() || path.join(".elo-client.lock").exists() {
        return Err(ReplicaError::Directory);
    }
    let lock = private_file(&path.join(".elo-replica.lock"))?;
    fs2::FileExt::try_lock_exclusive(&lock).map_err(|_| ReplicaError::Directory)?;
    let db_path = path.join("replica.sqlite");
    drop(private_file(&db_path)?);
    let mut c = Connection::open(db_path)?;
    c.busy_timeout(Duration::from_secs(5))?;
    c.pragma_update(None, "foreign_keys", true)?;
    c.pragma_update(None, "journal_mode", "WAL")?;
    c.pragma_update(None, "synchronous", "FULL")?;
    let version: i64 = c.pragma_query_value(None, "user_version", |r| r.get(0))?;
    let count: i64 = c.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
        [],
        |r| r.get(0),
    )?;
    if version == 0 && count == 0 {
        c.execute_batch(MIGRATION)?;
    } else if version != 1 && version != 2 {
        return Err(ReplicaError::Directory);
    }
    let schema =
        |conn: &Connection| -> std::result::Result<Vec<(String, String, String)>, rusqlite::Error> {
            let mut q=conn.prepare("SELECT type,name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name")?;
            q.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                .collect()
        };
    let reference = Connection::open_in_memory()?;
    reference.execute_batch(MIGRATION)?;
    if version == 2 {
        reference.execute_batch(DELEGATION_MIGRATION)?;
    }
    if schema(&c)? != schema(&reference)? {
        return Err(ReplicaError::Directory);
    }
    if version != 2 {
        c.execute_batch(DELEGATION_MIGRATION)?;
    }
    let pragmas:(String,i64,i64)=c.query_row("SELECT (SELECT journal_mode FROM pragma_journal_mode),(SELECT synchronous FROM pragma_synchronous),(SELECT foreign_keys FROM pragma_foreign_keys)",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
    let integrity: String = c.query_row("PRAGMA quick_check", [], |r| r.get(0))?;
    let fk: i64 = c.query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |r| {
        r.get(0)
    })?;
    if pragmas != ("wal".into(), 2, 1) || integrity != "ok" || fk != 0 {
        return Err(ReplicaError::Storage);
    }
    // The Replica signing secret is separate from all client/age secrets. Stored
    // in this private operator DB; an operator can already replace any receipt.
    let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let stored: Option<String> = tx
        .query_row(
            "SELECT value FROM node_meta WHERE key='signing_seed'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    let key = if let Some(seed) = stored {
        SigningKey::from_bytes(&hex(&seed).map_err(|_| ReplicaError::Storage)?)
    } else {
        let key = generate_signing_key().map_err(|_| ReplicaError::Storage)?;
        tx.execute(
            "INSERT INTO node_meta VALUES('signing_seed',?1)",
            [encode_hex(&key.to_bytes())],
        )?;
        key
    };
    let generation: Option<String> = tx
        .query_row(
            "SELECT value FROM node_meta WHERE key='storage_generation'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    let generation = if let Some(g) = generation {
        hex::<32>(&g).map_err(|_| ReplicaError::Storage)?;
        g
    } else {
        let g = random_hex::<32>().map_err(|_| ReplicaError::Storage)?;
        tx.execute(
            "INSERT INTO node_meta VALUES('storage_generation',?1)",
            [&g],
        )?;
        g
    };
    tx.commit()?;
    Ok(Db {
        connection: c,
        _lock: lock,
        key,
        generation,
    })
}
