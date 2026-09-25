//! Ciphertext-only store. A separate DB and process lock, no client vault/API.
use crate::{
    crypto::MAX_CIPHERTEXT,
    identity::generate_signing_key,
    ids::{IdentityId, MailboxId, ObjectId, PeerId, RecordId},
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
mod erasure;
mod maintenance;
mod packing;
const PACKING_MIGRATION: &str = include_str!("../../../migrations/006_replica_packing.sql");
const MESSAGE_LIFETIME_MIGRATION: &str =
    include_str!("../../../migrations/007_replica_message_lifetime.sql");
mod retention;
const ERASURE_MIGRATION: &str = include_str!("../../../migrations/005_replica_account_erasure.sql");
pub use retention::{SpaceStorage, VerifiedPruned};
const RETENTION_MIGRATION: &str = include_str!("../../../migrations/004_replica_retention.sql");
const MIGRATION: &str = include_str!("../../../migrations/001_replica.sql");
const DELEGATION_MIGRATION: &str =
    include_str!("../../../migrations/002_replica_mailbox_delegation.sql");
const ACCESS_MIGRATION: &str = include_str!("../../../migrations/003_replica_space_access.sql");
const NONCE_MIGRATION: &str = include_str!("../../../migrations/008_replica_request_nonces.sql");
const MESSAGE_ACCESS_MIGRATION: &str =
    include_str!("../../../migrations/009_replica_message_access.sql");
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
    #[error("server copy was removed by the Space owner")]
    Pruned(Vec<u8>),
    #[error("encrypted message body is outside its retention window")]
    Expired,
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
    pub requested_messages: Vec<ObjectId>,
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
            || !matches!(
                b.retention.as_str(),
                "manual-no-auto-gc" | "message-body-ttl" | "message-locator-30d"
            )
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
    admitted_devices: Arc<Mutex<std::collections::BTreeSet<crate::ids::RecordId>>>,
    revocations: crate::identity::revocations::Revocations,
    db: Arc<Mutex<Db>>,
    key: VerifyingKey,
}
impl ReplicaStore {
    pub async fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let registry_path = path.join("revoked-devices");
        let db = tokio::task::spawn_blocking(move || open_db(path))
            .await
            .map_err(|_| ReplicaError::Storage)??;
        let key = db.key.verifying_key();
        Ok(Self {
            admitted_devices: Arc::new(Mutex::new(Default::default())),
            revocations: crate::identity::revocations::Revocations::open(registry_path)
                .map_err(|_| ReplicaError::Storage)?,
            db: Arc::new(Mutex::new(db)),
            key,
        })
    }
    pub fn with_revocations(mut self, registry: crate::identity::revocations::Revocations) -> Self {
        self.revocations = registry;
        self
    }
    pub fn revocations(&self) -> &crate::identity::revocations::Revocations {
        &self.revocations
    }
    pub fn require_active_device(&self, credential: crate::ids::RecordId) -> Result<()> {
        if self
            .revocations
            .get(credential)
            .map_err(|_| ReplicaError::Storage)?
            .is_some()
        {
            return Err(ReplicaError::Unauthorized);
        }
        Ok(())
    }
    /// Loaded from the host's verified, durable General configuration at startup
    /// and after enrollment changes. No network request may add entries here.
    pub fn set_admitted_devices(&self, devices: Vec<crate::ids::RecordId>) -> Result<()> {
        *self
            .admitted_devices
            .lock()
            .map_err(|_| ReplicaError::Storage)? = devices.into_iter().collect();
        Ok(())
    }
    pub(crate) fn require_admitted_companion(
        &self,
        credential: crate::ids::RecordId,
    ) -> Result<()> {
        if self
            .admitted_devices
            .lock()
            .map_err(|_| ReplicaError::Storage)?
            .contains(&credential)
        {
            Ok(())
        } else {
            Err(ReplicaError::Unauthorized)
        }
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
        let descriptor = MailboxDescriptor::random()?;
        self.reserve_mailbox(descriptor.clone(), quota).await?;
        Ok(descriptor)
    }
    /// Local provisioning only. Persist the random descriptor before calling this
    /// method so a crash can be retried without allocating another mailbox.
    /// Existing capabilities and quotas can never be replaced through this API.
    pub async fn reserve_mailbox(&self, d: MailboxDescriptor, quota: u64) -> Result<()> {
        if quota == 0 || quota > MAX_INTEGER {
            return Err(ReplicaError::Invalid);
        }
        self.call(move |db| {
            let read = token_hash(&d.read_token)?;
            let write = token_hash(&d.write_token)?;
            if read == write { return Err(ReplicaError::Invalid); }
            let tx = db.connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let existing: Option<(Vec<u8>, Vec<u8>, i64)> = tx.query_row(
                "SELECT read_token_hash,write_token_hash,quota_bytes FROM mailboxes WHERE mailbox_id=?1",
                [d.mailbox_id.to_string()], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?))).optional()?;
            if let Some((r,w,q)) = existing {
                return if bool::from(r.as_slice().ct_eq(&read)) && bool::from(w.as_slice().ct_eq(&write)) && q == quota as i64 {
                    Ok(())
                } else { Err(ReplicaError::Conflict) };
            }
            tx.execute(
                "INSERT INTO mailboxes VALUES(?1,?2,?3,?4)",
                params![
                    d.mailbox_id.to_string(),
                    read,
                    write,
                    quota as i64
                ],
            )?;
            tx.commit()?;
            Ok(())
        })
        .await
    }
    /// Aggregate metadata for the local host operator. No ciphertext or tokens.
    /// Object counts are not message counts: clients also store other record types.
    pub async fn storage_statistics(&self) -> Result<serde_json::Value> {
        self.call(|db| {
            let (objects, bytes): (i64,i64) = db.connection.query_row(
                "SELECT COUNT(*),COALESCE(SUM(COALESCE(wire_size_bytes,size_bytes)),0) FROM objects", [], |r| Ok((r.get(0)?,r.get(1)?)))?;
            let mut statement = db.connection.prepare("WITH RECURSIVE tree(root,id) AS (SELECT mailbox_id,mailbox_id FROM mailboxes m WHERE NOT EXISTS(SELECT 1 FROM mailbox_delegations d WHERE d.mailbox_id=m.mailbox_id) UNION ALL SELECT tree.root,d.mailbox_id FROM mailbox_delegations d JOIN tree ON d.parent_id=tree.id), retained AS (SELECT DISTINCT tree.root,o.object_id,COALESCE(o.wire_size_bytes,o.size_bytes) AS size_bytes FROM tree JOIN deliveries d ON d.mailbox_id=tree.id JOIN objects o ON o.object_id=d.object_id) SELECT m.mailbox_id,m.quota_bytes,COUNT(r.object_id),COALESCE(SUM(r.size_bytes),0) FROM mailboxes m LEFT JOIN retained r ON r.root=m.mailbox_id WHERE NOT EXISTS(SELECT 1 FROM mailbox_delegations d WHERE d.mailbox_id=m.mailbox_id) GROUP BY m.mailbox_id")?;
            let mailboxes = statement.query_map([], |r| Ok(serde_json::json!({
                "id":r.get::<_,String>(0)?,"quota_bytes":r.get::<_,i64>(1)?,
                "objects":r.get::<_,i64>(2)?,"bytes":r.get::<_,i64>(3)?
            })))?.collect::<std::result::Result<Vec<_>,_>>()?;
            Ok(serde_json::json!({"objects":objects,"bytes":bytes,"mailboxes":mailboxes}))
        }).await
    }
    /// Local, explicitly authorized hosting deletion. Revoke the root and all
    /// descendants atomically; retain objects still referenced by other mailboxes.
    pub async fn delete_mailbox_tree(&self, mailbox: MailboxId) -> Result<()> {
        self.call(move |db| {
            db.connection.pragma_update(None,"secure_delete","ON")?;
            let tx=db.connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let ids={
                let mut q=tx.prepare("WITH RECURSIVE scope(id) AS (SELECT ?1 UNION SELECT mailbox_id FROM mailbox_delegations JOIN scope ON parent_id=scope.id) SELECT id FROM scope")?;
                q.query_map([mailbox.to_string()],|r|r.get::<_,String>(0))?.collect::<std::result::Result<Vec<_>,_>>()?
            };
            for id in &ids { tx.execute("DELETE FROM deliveries WHERE mailbox_id=?1",[id])?; }
            for id in &ids { tx.execute("DELETE FROM mailbox_delegations WHERE mailbox_id=?1",[id])?; }
            for id in &ids { tx.execute("DELETE FROM mailboxes WHERE mailbox_id=?1",[id])?; }
            tx.execute("DELETE FROM objects WHERE NOT EXISTS (SELECT 1 FROM deliveries d WHERE d.object_id=objects.object_id)",[])?;
            tx.commit()?;
            maintenance::reclaim(&db.connection)?;
            Ok(())
        }).await
    }
    /// Local host administration; no public endpoint can change this policy.
    pub async fn set_space_members(
        &self,
        mailbox: MailboxId,
        identities: Vec<crate::ids::IdentityId>,
    ) -> Result<()> {
        self.call(move |db| {
            let root = retention::root(&db.connection, mailbox)?;
            let tx = db
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute(
                "INSERT OR IGNORE INTO space_access_roots VALUES(?1)",
                [mailbox.to_string()],
            )?;
            tx.execute(
                "DELETE FROM space_access_members WHERE mailbox_id=?1",
                [mailbox.to_string()],
            )?;
            for identity in identities {
                tx.execute(
                    "INSERT OR IGNORE INTO space_access_members SELECT ?1,?2 WHERE NOT EXISTS(SELECT 1 FROM erased_identities WHERE identity_id=?2)",
                    params![mailbox.to_string(), identity.to_string()],
                )?;
            }
            tx.execute(
                "DELETE FROM message_requests WHERE root_mailbox_id=?1 AND requester_identity NOT IN (SELECT identity_id FROM space_access_members WHERE mailbox_id=?1)",
                [&root],
            )?;
            tx.execute(
                "DELETE FROM message_acceptances WHERE root_mailbox_id=?1 AND accepting_identity NOT IN (SELECT identity_id FROM space_access_members WHERE mailbox_id=?1)",
                [&root],
            )?;
            tx.commit()?;
            Ok(())
        })
        .await
    }
    pub async fn authorize_identity(
        &self,
        mailbox: MailboxId,
        identity: Option<crate::ids::IdentityId>,
    ) -> Result<()> {
        self.call(move |db| {
            let denied: i64 = db.connection.query_row("WITH RECURSIVE ancestry(id) AS (SELECT ?1 UNION SELECT d.parent_id FROM mailbox_delegations d JOIN ancestry a ON d.mailbox_id=a.id) SELECT count(*) FROM ancestry JOIN space_access_roots r ON r.mailbox_id=ancestry.id WHERE NOT EXISTS(SELECT 1 FROM space_access_members m WHERE m.mailbox_id=r.mailbox_id AND m.identity_id=?2)", params![mailbox.to_string(),identity.map(|id|id.to_string())], |r|r.get(0))?;
            if denied == 0 { Ok(()) } else { Err(ReplicaError::Unauthorized) }
        }).await
    }
    pub async fn authorize(&self, mailbox: MailboxId, token: String, write: bool) -> Result<()> {
        self.call(move |db| authorize(&db.connection, mailbox, &token, write))
            .await
    }
    pub(crate) async fn consume_access(
        &self,
        access: crate::sync::access::VerifiedAccess,
    ) -> Result<()> {
        self.call(move |db| {
            let time = now()?;
            if access.expires < time {
                return Err(ReplicaError::Unauthorized);
            }
            let tx = db
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute(
                "DELETE FROM access_nonces WHERE expires_at<?1",
                [time as i64],
            )?;
            let credential = access.credential.to_string();
            let used: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM access_nonces WHERE credential_id=?1 AND nonce=?2)",
                params![credential, access.nonce],
                |r| r.get(0),
            )?;
            if used {
                return Err(ReplicaError::Unauthorized);
            }
            let total: i64 =
                tx.query_row("SELECT COUNT(*) FROM access_nonces", [], |r| r.get(0))?;
            let own: i64 = tx.query_row(
                "SELECT COUNT(*) FROM access_nonces WHERE credential_id=?1",
                [&credential],
                |r| r.get(0),
            )?;
            if total >= 65_536 || own >= 4096 {
                return Err(ReplicaError::Quota);
            }
            tx.execute(
                "INSERT INTO access_nonces VALUES(?1,?2,?3)",
                params![credential, access.nonce, access.expires as i64],
            )?;
            tx.commit()?;
            Ok(())
        })
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
            // Expiry ends the capability and releases its subtree's count and bytes.
            let expired = {
                let mut q = tx.prepare("WITH RECURSIVE expired(id) AS (SELECT mailbox_id FROM mailbox_delegations WHERE expires_at<=?1 UNION SELECT d.mailbox_id FROM mailbox_delegations d JOIN expired e ON d.parent_id=e.id) SELECT id FROM expired")?;
                q.query_map([time as i64], |r| r.get::<_, String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?
            };
            for id in &expired { tx.execute("DELETE FROM deliveries WHERE mailbox_id=?1", [id])?; }
            for id in &expired { tx.execute("DELETE FROM mailbox_delegations WHERE mailbox_id=?1", [id])?; }
            for id in &expired { tx.execute("DELETE FROM mailboxes WHERE mailbox_id=?1", [id])?; }
            if !expired.is_empty() {
                tx.execute("DELETE FROM objects WHERE NOT EXISTS(SELECT 1 FROM deliveries d WHERE d.object_id=objects.object_id)", [])?;
            }

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
        self.post_classified(mailbox, token, id, bytes, hint, false)
            .await
    }
    pub async fn post_classified(
        &self,
        mailbox: MailboxId,
        token: String,
        id: ObjectId,
        bytes: Vec<u8>,
        hint: TransferHint,
        message: bool,
    ) -> Result<(bool, Vec<u8>)> {
        self.post_inner(mailbox, token, id, bytes, hint, message, None)
            .await
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Keep the authenticated upload API aligned with post_classified, adding only its verified actor"
    )]
    pub async fn post_authenticated(
        &self,
        mailbox: MailboxId,
        token: String,
        id: ObjectId,
        bytes: Vec<u8>,
        hint: TransferHint,
        message: bool,
        actor: Option<crate::retention_access::Actor>,
    ) -> Result<(bool, Vec<u8>)> {
        self.post_inner(mailbox, token, id, bytes, hint, message, actor)
            .await
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Shared upload implementation retains the explicit request fields and verified actor"
    )]
    async fn post_inner(
        &self,
        mailbox: MailboxId,
        token: String,
        id: ObjectId,
        bytes: Vec<u8>,
        hint: TransferHint,
        message: bool,
        actor: Option<crate::retention_access::Actor>,
    ) -> Result<(bool, Vec<u8>)> {
        let revocations = self.revocations.clone();
        self.call(move|db|{
   authorize(&db.connection,mailbox,&token,true)?;
   let identity = actor.map(|actor| actor.identity);
   if let Some(actor) = actor { retention::authorize_actor(&db.connection, &revocations, mailbox, actor)?; }
   if bytes.is_empty()||bytes.len()>MAX_CIPHERTEXT||ObjectId::of_ciphertext(&bytes)!=id{return Err(ReplicaError::Invalid);}
   let time=now()?;
   retention::sweep(&db.connection,time)?;
   retention::check_pruned(db,mailbox,id)?;
   let content = crate::erasure::inspect(&bytes).map_err(|_| ReplicaError::Invalid)?;
   let retention = retention::classify(content.as_ref(), message);
   retention::check_upload(&db.connection,&revocations,mailbox,id,&retention,identity,time)?;
   let mut subjects = content.as_ref().map(|value| value.subjects.clone()).unwrap_or_default();
   if subjects.is_empty() {
    let required: bool = db.connection.query_row("SELECT EXISTS(SELECT 1 FROM node_meta WHERE key='require_content_owner' AND value='yes')", [], |row|row.get(0))?;
    if required {
     // Pairing chunks use a temporary delegated mailbox and cannot be wrapped
     // without changing their content-addressed protocol. Attribute them to the
     // authenticated account instead; permanent mailboxes still require a claim.
     let temporary: bool = db.connection.query_row("SELECT EXISTS(SELECT 1 FROM mailbox_delegations WHERE mailbox_id=?1)", [mailbox.to_string()], |row|row.get(0))?;
     if !temporary { return Err(ReplicaError::Invalid); }
     subjects.push(identity.ok_or(ReplicaError::Unauthorized)?);
    }
   }
   for identity in &subjects {
    let erased: bool = db.connection.query_row("SELECT EXISTS(SELECT 1 FROM erased_identities WHERE identity_id=?1)",[identity.to_string()],|row|row.get(0))?;
    if erased { return Err(ReplicaError::Unauthorized); }
   }
   let tx=db.connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
   let retention_root=retention::root(&tx,mailbox)?;
   let retention_delta=retention::metadata_delta(&tx,&retention_root,id,&retention)?;
   let old:Option<(i64,String)>=tx.query_row("SELECT arrival_seq,transfer_hint FROM deliveries WHERE mailbox_id=?1 AND object_id=?2",params![mailbox.to_string(),id.to_string()],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
   let inserted=old.is_none();
   let seq=if let Some((seq,mode))=old {
    let stored=packing::load(&tx,id)?;
    if stored!=bytes||mode!=hint.as_str(){return Err(ReplicaError::Conflict);}seq
   }else{
    for ancestor in ancestors(&tx, mailbox)? {
     let quota:i64=tx.query_row("SELECT quota_bytes FROM mailboxes WHERE mailbox_id=?1",[&ancestor],|r|r.get(0))?;
     let used:i64=tx.query_row("WITH RECURSIVE tree(id) AS (SELECT ?1 UNION ALL SELECT mailbox_id FROM mailbox_delegations JOIN tree ON parent_id=tree.id) SELECT coalesce(sum(COALESCE(o.wire_size_bytes,o.size_bytes)),0) FROM deliveries d JOIN objects o USING(object_id) JOIN tree ON d.mailbox_id=tree.id",[&ancestor],|r|r.get(0))?;
     let used=used.saturating_add(retention::metadata_usage(&tx,&ancestor)?);
     let delta=if ancestor==retention_root { retention_delta } else { 0 };
     if (bytes.len() as i64).saturating_add(delta)>quota-used{return Err(ReplicaError::Quota);}
    }
    packing::insert(&tx,id,&bytes,content.as_ref(),time)?;
    for identity in &subjects { tx.execute("INSERT OR IGNORE INTO object_owners VALUES(?1,?2)",params![id.to_string(),identity.to_string()])?; }
    if message && subjects.is_empty() { tx.execute("UPDATE node_meta SET value='legacy' WHERE key='erasure_coverage'",[])?; }
    let stored=packing::load(&tx,id)?;if stored!=bytes{return Err(ReplicaError::Conflict);}
    tx.execute("INSERT INTO deliveries(mailbox_id,object_id,transfer_hint) VALUES(?1,?2,?3)",params![mailbox.to_string(),id.to_string(),hint.as_str()])?;
    let seq=tx.last_insert_rowid();
    retention::record_upload(&tx,mailbox,id,&retention,time)?;
    seq
   };
   let stored_time:i64=tx.query_row("SELECT stored_local_ms FROM objects WHERE object_id=?1",[id.to_string()],|r|r.get(0))?;
   tx.commit()?;
   let policy=match retention { retention::UploadRetention::MessageBody{..}=>"message-body-ttl",retention::UploadRetention::MessageLocator{..}=>"message-locator-30d",_=>"manual-no-auto-gc"};
   let body=ReceiptBody{v:1,kind:"storage.receipt".into(),peer_id:peer_id(&db.key.verifying_key()),mailbox_id:mailbox,object_id:id,size_bytes:bytes.len() as u64,arrival_seq:seq as u64,storage_generation:db.generation.clone(),storage_class:"sqlite-wal-full".into(),retention:policy.into(),nonce:random_hex::<16>().map_err(|_|ReplicaError::Storage)?,stored_local_ms:stored_time as u64};
   let body=serde_json::to_vec(&body).map_err(|_|ReplicaError::Storage)?;let receipt=SignedRecord::sign(&body,&db.key).map_err(|_|ReplicaError::Storage)?;
   Ok((inserted,receipt.bytes().to_vec()))
  }).await
    }
    pub async fn get(&self, mailbox: MailboxId, token: String, id: ObjectId) -> Result<Vec<u8>> {
        self.call(move |db| {
            authorize(&db.connection, mailbox, &token, false)?;
            retention::sweep(&db.connection, now()?)?;
            retention::check_pruned(db, mailbox, id)?;
            let delivered: bool = db.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM deliveries WHERE mailbox_id=?1 AND object_id=?2)",
                params![mailbox.to_string(), id.to_string()],
                |r| r.get(0),
            )?;
            if !delivered {
                return Err(ReplicaError::NotFound);
            }
            packing::load(&db.connection, id)
        })
        .await
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
        let revocations = self.revocations.clone();
        self.call(move|db|{
   authorize(&db.connection,mailbox,&token,false)?;
   let time=now()?;
   retention::sweep(&db.connection,time)?;
   let head:i64=db.connection.query_row("SELECT coalesce(max(arrival_seq),0) FROM deliveries WHERE mailbox_id=?1",[mailbox.to_string()],|r|r.get(0))?;
   let mut q=db.connection.prepare("SELECT d.arrival_seq,d.object_id,COALESCE(o.wire_size_bytes,o.size_bytes),d.transfer_hint FROM deliveries d JOIN objects o USING(object_id) WHERE d.mailbox_id=?1 AND d.arrival_seq>?2 ORDER BY d.arrival_seq LIMIT ?3")?;
   let rows=q.query_map(params![mailbox.to_string(),after as i64,limit as i64],|r|Ok((r.get::<_,i64>(0)?,r.get::<_,String>(1)?,r.get::<_,i64>(2)?,r.get::<_,String>(3)?)))?;
   let mut entries=Vec::new();for row in rows{let (arrival,id,size,hint)=row?;entries.push(InventoryEntry{arrival_seq:arrival as u64,object_id:id.parse().map_err(|_|ReplicaError::Storage)?,size_bytes:size as u64,transfer_hint:match hint.as_str(){"eager"=>TransferHint::Eager,"lazy"=>TransferHint::Lazy,_=>return Err(ReplicaError::Storage)}});}
   let requested_messages=retention::active_requests(&db.connection,&revocations,mailbox,time)?;
   Ok(Inventory{storage_generation:db.generation.clone(),head:head as u64,entries,requested_messages})
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
    let version: i64 = c.pragma_query_value(None, "user_version", |r| r.get(0))?;
    let count: i64 = c.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
        [],
        |r| r.get(0),
    )?;
    if version == 0 && count == 0 {
        c.pragma_update(None, "auto_vacuum", "INCREMENTAL")?;
    } else if !(1..=9).contains(&version) {
        return Err(ReplicaError::Directory);
    }
    c.pragma_update(None, "journal_mode", "WAL")?;
    c.pragma_update(None, "synchronous", "FULL")?;
    if version == 0 && count == 0 {
        c.execute_batch(MIGRATION)?;
    }
    let schema =
        |conn: &Connection| -> std::result::Result<Vec<(String, String, String)>, rusqlite::Error> {
            let mut q=conn.prepare("SELECT type,name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name")?;
            q.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                .collect()
        };
    let reference = Connection::open_in_memory()?;
    reference.execute_batch(MIGRATION)?;
    if version >= 2 {
        reference.execute_batch(DELEGATION_MIGRATION)?;
    }
    if version >= 3 {
        reference.execute_batch(ACCESS_MIGRATION)?;
    }
    if version >= 4 {
        reference.execute_batch(RETENTION_MIGRATION)?;
    }
    if version >= 5 {
        reference.execute_batch(ERASURE_MIGRATION)?;
    }
    if version >= 6 {
        reference.execute_batch(PACKING_MIGRATION)?;
    }
    if version >= 7 {
        reference.execute_batch(MESSAGE_LIFETIME_MIGRATION)?;
    }
    if version >= 8 {
        reference.execute_batch(NONCE_MIGRATION)?;
    }
    if version >= 9 {
        reference.execute_batch(MESSAGE_ACCESS_MIGRATION)?;
    }
    if schema(&c)? != schema(&reference)? {
        return Err(ReplicaError::Directory);
    }
    if version < 2 {
        c.execute_batch(DELEGATION_MIGRATION)?;
    }
    if version < 3 {
        c.execute_batch(ACCESS_MIGRATION)?;
    }
    if version < 4 {
        c.execute_batch(RETENTION_MIGRATION)?;
    }
    if version < 5 {
        c.execute_batch(ERASURE_MIGRATION)?;
    }
    if version < 6 {
        c.execute_batch(PACKING_MIGRATION)?;
    }
    if version < 7 {
        c.execute_batch(MESSAGE_LIFETIME_MIGRATION)?;
    }
    if version < 8 {
        c.execute_batch(NONCE_MIGRATION)?;
    }
    if version < 9 {
        c.execute_batch(MESSAGE_ACCESS_MIGRATION)?;
    }
    c.pragma_update(None, "journal_size_limit", 4 * 1024 * 1024)?;
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
