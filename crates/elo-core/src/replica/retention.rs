//! Explicit server-copy cleanup. Local history and control records are untouched.
use super::*;

const LOCATOR_LIFETIME_MS: u64 = 30 * 24 * 60 * 60 * 1000;
const REQUEST_LIFETIME_MS: u64 = 5 * 60 * 1000;
const ACCEPTANCE_LIFETIME_MS: u64 = 24 * 60 * 60 * 1000;
const METADATA_BYTES: i64 = 256;

#[derive(Clone)]
pub(super) enum UploadRetention {
    Retain,
    LegacyMessage,
    MessageBody {
        locator_nonce: String,
        record_id: RecordId,
        lifetime_seconds: u64,
        issuer: IdentityId,
        direct_peer: Option<IdentityId>,
    },
    MessageLocator {
        locator_nonce: String,
        body_object_id: ObjectId,
        record_id: RecordId,
        lifetime_seconds: u64,
        issuer: IdentityId,
    },
}

pub(super) fn classify(
    content: Option<&crate::erasure::Content<'_>>,
    legacy_message: bool,
) -> UploadRetention {
    let Some(content) = content else {
        return if legacy_message {
            UploadRetention::LegacyMessage
        } else {
            UploadRetention::Retain
        };
    };
    match content.retention.clone() {
        Some(crate::erasure::RetentionClaim::MessageBody {
            locator_nonce,
            record_id,
            lifetime_seconds,
            direct_peer,
        }) => UploadRetention::MessageBody {
            locator_nonce,
            record_id,
            lifetime_seconds,
            issuer: content.credential.identity(),
            direct_peer,
        },
        Some(crate::erasure::RetentionClaim::MessageLocator {
            locator_nonce,
            body_object_id,
            record_id,
            lifetime_seconds,
        }) => UploadRetention::MessageLocator {
            locator_nonce,
            body_object_id,
            record_id,
            lifetime_seconds,
            issuer: content.credential.identity(),
        },
        None if legacy_message => UploadRetention::LegacyMessage,
        None => UploadRetention::Retain,
    }
}

pub(super) fn root(c: &Connection, mailbox: MailboxId) -> Result<String> {
    c.query_row(
        "WITH RECURSIVE chain(id,parent) AS (SELECT ?1,(SELECT parent_id FROM mailbox_delegations WHERE mailbox_id=?1) UNION ALL SELECT d.parent_id,(SELECT parent_id FROM mailbox_delegations WHERE mailbox_id=d.parent_id) FROM mailbox_delegations d JOIN chain ON d.mailbox_id=chain.id) SELECT id FROM chain WHERE parent IS NULL LIMIT 1",
        [mailbox.to_string()],
        |row| row.get(0),
    )
    .map_err(Into::into)
}

fn remove_body(c: &Connection, root: &str, object: &str, time: u64) -> Result<()> {
    c.execute(
        "WITH RECURSIVE tree(id) AS (SELECT ?1 UNION SELECT d.mailbox_id FROM mailbox_delegations d JOIN tree ON d.parent_id=tree.id) DELETE FROM deliveries WHERE object_id=?2 AND mailbox_id IN (SELECT id FROM tree)",
        params![root, object],
    )?;
    c.execute(
        "UPDATE message_bodies SET expired_local_ms=COALESCE(expired_local_ms,?3),refill_until_ms=NULL WHERE root_mailbox_id=?1 AND object_id=?2",
        params![root, object, time as i64],
    )?;
    c.execute(
        "DELETE FROM objects WHERE object_id=?1 AND NOT EXISTS(SELECT 1 FROM deliveries WHERE object_id=?1)",
        [object],
    )?;
    Ok(())
}

pub(super) fn sweep(c: &Connection, time: u64) -> Result<bool> {
    let mut changed = false;
    let expired = {
        let mut q = c.prepare(
            "SELECT root_mailbox_id,object_id FROM message_bodies WHERE expired_local_ms IS NULL AND expires_local_ms<=?1",
        )?;
        q.query_map([time as i64], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?
    };
    for (root, object) in expired {
        remove_body(c, &root, &object, time)?;
        changed = true;
    }
    let locators = {
        let mut q = c.prepare(
            "SELECT root_mailbox_id,object_id,body_object_id FROM message_locators WHERE expires_local_ms<=?1",
        )?;
        q.query_map([time as i64], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?
    };
    for (root, object, body) in locators {
        c.execute(
            "WITH RECURSIVE tree(id) AS (SELECT ?1 UNION SELECT d.mailbox_id FROM mailbox_delegations d JOIN tree ON d.parent_id=tree.id) DELETE FROM deliveries WHERE object_id=?2 AND mailbox_id IN (SELECT id FROM tree)",
            params![root, object],
        )?;
        changed = true;
        c.execute(
            "DELETE FROM message_locators WHERE root_mailbox_id=?1 AND object_id=?2",
            params![root, object],
        )?;
        c.execute(
            "DELETE FROM message_bodies WHERE root_mailbox_id=?1 AND object_id=?2",
            params![root, body],
        )?;
        c.execute(
            "DELETE FROM objects WHERE object_id=?1 AND NOT EXISTS(SELECT 1 FROM deliveries WHERE object_id=?1)",
            [object],
        )?;
    }
    changed |= c.execute(
        "DELETE FROM message_requests WHERE expires_local_ms<=?1",
        [time as i64],
    )? > 0;
    changed |= c.execute(
        "DELETE FROM message_acceptances WHERE expires_local_ms<=?1",
        [time as i64],
    )? > 0;
    Ok(changed)
}

pub(super) fn check_upload(
    c: &Connection,
    mailbox: MailboxId,
    object: ObjectId,
    retention: &UploadRetention,
    actor: Option<IdentityId>,
    time: u64,
) -> Result<()> {
    let root = root(c, mailbox)?;
    match retention {
        UploadRetention::MessageLocator { issuer, .. } => {
            if actor != Some(*issuer) {
                return Err(ReplicaError::Unauthorized);
            }
        }
        UploadRetention::MessageBody {
            locator_nonce,
            record_id,
            lifetime_seconds,
            issuer,
            direct_peer,
        } => {
            let previous: Option<(String, String, i64, String, Option<String>, Option<i64>)> = c
                .query_row(
                    "SELECT locator_nonce,record_id,lifetime_seconds,originating_issuer,direct_peer,expired_local_ms FROM message_bodies WHERE root_mailbox_id=?1 AND object_id=?2",
                    params![root, object.to_string()],
                    |r| {
                        Ok((
                            r.get(0)?,
                            r.get(1)?,
                            r.get(2)?,
                            r.get(3)?,
                            r.get(4)?,
                            r.get(5)?,
                        ))
                    },
                )
                .optional()?;
            if let Some(previous) = previous {
                if previous.0 != locator_nonce.as_str()
                    || previous.1 != record_id.to_string()
                    || previous.2 != *lifetime_seconds as i64
                    || previous.3 != issuer.to_string()
                    || previous.4 != direct_peer.map(|v| v.to_string())
                {
                    return Err(ReplicaError::Conflict);
                }
                if previous.5.is_none() {
                    return Ok(());
                }
                let window: Option<i64> = c
                    .query_row(
                        "SELECT MAX(expires_local_ms) FROM message_requests WHERE root_mailbox_id=?1 AND body_object_id=?2 AND expires_local_ms>?3",
                        params![root, object.to_string(), time as i64],
                        |r| r.get(0),
                    )?;
                if window.is_none() {
                    return Err(ReplicaError::Expired);
                }
            } else {
                if actor != Some(*issuer) {
                    return Err(ReplicaError::Unauthorized);
                }
                let locator: Option<(String, String, i64)> = c
                    .query_row(
                        "SELECT locator_nonce,record_id,lifetime_seconds FROM message_locators WHERE root_mailbox_id=?1 AND body_object_id=?2 AND expires_local_ms>?3",
                        params![root, object.to_string(), time as i64],
                        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                    )
                    .optional()?;
                if locator
                    != Some((
                        locator_nonce.clone(),
                        record_id.to_string(),
                        *lifetime_seconds as i64,
                    ))
                {
                    return Err(ReplicaError::Invalid);
                }
            }
        }
        UploadRetention::Retain | UploadRetention::LegacyMessage => {}
    }
    Ok(())
}

pub(super) fn record_upload(
    c: &Connection,
    mailbox: MailboxId,
    object: ObjectId,
    retention: &UploadRetention,
    time: u64,
) -> Result<()> {
    let root = root(c, mailbox)?;
    match retention {
        UploadRetention::MessageLocator {
            locator_nonce,
            body_object_id,
            record_id,
            lifetime_seconds,
            ..
        } => {
            c.execute(
                "INSERT INTO message_locators VALUES(?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(root_mailbox_id,object_id) DO NOTHING",
                params![root, object.to_string(), body_object_id.to_string(), record_id.to_string(), locator_nonce, *lifetime_seconds as i64, time as i64, time.saturating_add(LOCATOR_LIFETIME_MS) as i64],
            )?;
        }
        UploadRetention::MessageBody {
            locator_nonce,
            record_id,
            lifetime_seconds,
            issuer,
            direct_peer,
        } => {
            let old: Option<i64> = c
                .query_row(
                    "SELECT expires_local_ms FROM message_bodies WHERE root_mailbox_id=?1 AND object_id=?2",
                    params![root, object.to_string()],
                    |r| r.get(0),
                )
                .optional()?;
            let expiry = if old.is_some() {
                c.query_row(
                    "SELECT MAX(expires_local_ms) FROM message_requests WHERE root_mailbox_id=?1 AND body_object_id=?2 AND expires_local_ms>?3",
                    params![root, object.to_string(), time as i64],
                    |r| r.get::<_, i64>(0),
                )? as u64
            } else {
                time.saturating_add(lifetime_seconds.saturating_mul(1000))
            };
            c.execute(
                "INSERT INTO message_bodies VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,NULL,NULL) ON CONFLICT(root_mailbox_id,object_id) DO UPDATE SET expires_local_ms=excluded.expires_local_ms,expired_local_ms=NULL,refill_until_ms=excluded.expires_local_ms",
                params![root, object.to_string(), record_id.to_string(), locator_nonce, issuer.to_string(), direct_peer.map(|v|v.to_string()), *lifetime_seconds as i64, time as i64, expiry as i64],
            )?;
        }
        UploadRetention::LegacyMessage => {
            c.execute(
                "INSERT OR IGNORE INTO message_copies VALUES(?1,?2,?3)",
                params![mailbox.to_string(), object.to_string(), time as i64],
            )?;
        }
        UploadRetention::Retain => {}
    }
    Ok(())
}

pub(super) fn metadata_usage(c: &Connection, root: &str) -> Result<i64> {
    let count: i64 = c.query_row(
        "SELECT (SELECT count(*) FROM message_bodies WHERE root_mailbox_id=?1)+(SELECT count(*) FROM message_locators WHERE root_mailbox_id=?1)+(SELECT count(*) FROM message_requests WHERE root_mailbox_id=?1)+(SELECT count(*) FROM message_acceptances WHERE root_mailbox_id=?1)",
        [root],
        |r| r.get(0),
    )?;
    Ok(count.saturating_mul(METADATA_BYTES))
}

pub(super) fn metadata_delta(
    c: &Connection,
    root: &str,
    object: ObjectId,
    retention: &UploadRetention,
) -> Result<i64> {
    let table = match retention {
        UploadRetention::MessageBody { .. } => Some("message_bodies"),
        UploadRetention::MessageLocator { .. } => Some("message_locators"),
        UploadRetention::Retain | UploadRetention::LegacyMessage => None,
    };
    let Some(table) = table else { return Ok(0) };
    let exists: bool = c.query_row(
        &format!("SELECT EXISTS(SELECT 1 FROM {table} WHERE root_mailbox_id=?1 AND object_id=?2)"),
        params![root, object.to_string()],
        |row| row.get(0),
    )?;
    Ok(if exists { 0 } else { METADATA_BYTES })
}

fn retained_usage(c: &Connection, root: &str) -> Result<i64> {
    c.query_row(
        "WITH RECURSIVE tree(id) AS (SELECT ?1 UNION ALL SELECT mailbox_id FROM mailbox_delegations JOIN tree ON parent_id=tree.id) SELECT COALESCE(SUM(COALESCE(o.wire_size_bytes,o.size_bytes)),0) FROM deliveries d JOIN tree ON d.mailbox_id=tree.id JOIN objects o USING(object_id)",
        [root],
        |row| row.get(0),
    )
    .map_err(Into::into)
}

fn ensure_metadata_room(c: &Connection, root: &str, delta: i64) -> Result<()> {
    if delta <= 0 {
        return Ok(());
    }
    let quota: i64 = c.query_row(
        "SELECT quota_bytes FROM mailboxes WHERE mailbox_id=?1",
        [root],
        |row| row.get(0),
    )?;
    let used = retained_usage(c, root)?.saturating_add(metadata_usage(c, root)?);
    if delta > quota.saturating_sub(used) {
        return Err(ReplicaError::Quota);
    }
    Ok(())
}

pub(super) fn active_requests(
    c: &Connection,
    mailbox: MailboxId,
    time: u64,
) -> Result<Vec<ObjectId>> {
    let root = root(c, mailbox)?;
    let mut query = c.prepare(
        "SELECT DISTINCT body_object_id FROM message_requests WHERE root_mailbox_id=?1 AND expires_local_ms>?2 ORDER BY body_object_id LIMIT 128",
    )?;
    let rows = query.query_map(params![root, time as i64], |row| row.get::<_, String>(0))?;
    let mut result = Vec::new();
    for value in rows {
        result.push(value?.parse().map_err(|_| ReplicaError::Storage)?);
    }
    Ok(result)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrunedBody {
    v: u64,
    kind: String,
    peer_id: PeerId,
    mailbox_id: MailboxId,
    object_id: ObjectId,
    pruned_local_ms: u64,
}

/// A signed refusal to retain this copy, never a successful storage receipt.
#[derive(Clone, Debug)]
pub struct VerifiedPruned {
    record: SignedRecord,
    body: PrunedBody,
}
impl VerifiedPruned {
    pub fn verify(
        bytes: &[u8],
        key: &VerifyingKey,
        mailbox: MailboxId,
        object: ObjectId,
    ) -> Result<Self> {
        let record = SignedRecord::parse(bytes).map_err(|_| ReplicaError::Invalid)?;
        record
            .verify_signature(key)
            .map_err(|_| ReplicaError::Invalid)?;
        let body: PrunedBody = record.decode().map_err(|_| ReplicaError::Invalid)?;
        if body.v != 1
            || body.kind != "storage.pruned"
            || body.peer_id != peer_id(key)
            || body.mailbox_id != mailbox
            || body.object_id != object
            || body.pruned_local_ms > MAX_INTEGER
        {
            return Err(ReplicaError::Invalid);
        }
        Ok(Self { record, body })
    }
    pub fn peer(&self) -> PeerId {
        self.body.peer_id
    }
    pub fn mailbox(&self) -> MailboxId {
        self.body.mailbox_id
    }
    pub fn object(&self) -> ObjectId {
        self.body.object_id
    }
    pub fn bytes(&self) -> &[u8] {
        self.record.bytes()
    }
}

pub(super) fn check_pruned(db: &Db, mailbox: MailboxId, object: ObjectId) -> Result<()> {
    let deleted: Option<i64> = db.connection.query_row(
        "WITH RECURSIVE scope(id) AS (SELECT ?1 UNION SELECT d.parent_id FROM mailbox_delegations d JOIN scope ON d.mailbox_id=scope.id) SELECT p.pruned_local_ms FROM pruned_objects p JOIN scope ON p.root_mailbox_id=scope.id WHERE p.object_id=?2 LIMIT 1",
        params![mailbox.to_string(),object.to_string()], |r| r.get(0)).optional()?;
    if let Some(pruned_local_ms) = deleted {
        let body = PrunedBody {
            v: 1,
            kind: "storage.pruned".into(),
            peer_id: peer_id(&db.key.verifying_key()),
            mailbox_id: mailbox,
            object_id: object,
            pruned_local_ms: pruned_local_ms as u64,
        };
        let bytes = serde_json::to_vec(&body).map_err(|_| ReplicaError::Storage)?;
        let record = SignedRecord::sign(&bytes, &db.key).map_err(|_| ReplicaError::Storage)?;
        return Err(ReplicaError::Pruned(record.bytes().to_vec()));
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SpaceStorage {
    pub used_bytes: u64,
    pub quota_bytes: u64,
    pub before_ms: u64,
    pub removable_copies: u64,
    pub removable_bytes: u64,
}

const TREE: &str = "WITH RECURSIVE tree(id) AS (SELECT ?1 UNION SELECT d.mailbox_id FROM mailbox_delegations d JOIN tree ON d.parent_id=tree.id)";
// If any copy of an object in this Space is unclassified, preserve the object.
// This prevents a duplicate upload from relabeling a protected control record.
const CANDIDATES: &str = "SELECT m.object_id FROM message_copies m JOIN tree ON tree.id=m.mailbox_id GROUP BY m.object_id HAVING MAX(m.stored_local_ms) < ?2 AND NOT EXISTS (SELECT 1 FROM deliveries d JOIN tree t ON t.id=d.mailbox_id LEFT JOIN message_copies c ON c.mailbox_id=d.mailbox_id AND c.object_id=d.object_id WHERE d.object_id=m.object_id AND c.object_id IS NULL)";

fn usage(c: &Connection, root: MailboxId, before: u64) -> Result<SpaceStorage> {
    // Only a complete Space root can be managed through this local host API.
    let quota: i64 = c.query_row("SELECT quota_bytes FROM mailboxes m WHERE mailbox_id=?1 AND NOT EXISTS(SELECT 1 FROM mailbox_delegations d WHERE d.mailbox_id=m.mailbox_id)", [root.to_string()],|r|r.get(0)).optional()?.ok_or(ReplicaError::Invalid)?;
    let used =
        retained_usage(c, &root.to_string())?.saturating_add(metadata_usage(c, &root.to_string())?);
    let (count, bytes): (i64,i64) = c.query_row(&format!("{TREE}, candidates AS ({CANDIDATES}) SELECT COUNT(*),COALESCE(SUM(COALESCE(o.wire_size_bytes,o.size_bytes)),0) FROM deliveries d JOIN tree ON tree.id=d.mailbox_id JOIN objects o USING(object_id) JOIN candidates ON candidates.object_id=d.object_id"), params![root.to_string(),before as i64],|r|Ok((r.get(0)?,r.get(1)?)))?;
    Ok(SpaceStorage {
        used_bytes: used as u64,
        quota_bytes: quota as u64,
        before_ms: before,
        removable_copies: count as u64,
        removable_bytes: bytes as u64,
    })
}

impl ReplicaStore {
    /// Bounded hosting worker pass. Request paths also sweep before serving so
    /// correctness does not depend on the timer, while this reclaims dormant Spaces.
    pub async fn maintain_message_lifetime(&self) -> Result<()> {
        self.call(|db| {
            if sweep(&db.connection, now()?)? {
                maintenance::reclaim(&db.connection)?;
            }
            Ok(())
        })
        .await
    }

    pub async fn request_message(
        &self,
        mailbox: MailboxId,
        identity: IdentityId,
        object: ObjectId,
        record: RecordId,
    ) -> Result<()> {
        self.call(move |db| {
            let time = now()?;
            sweep(&db.connection, time)?;
            let root = root(&db.connection, mailbox)?;
            let available: bool = db.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM message_bodies b JOIN message_locators l ON l.root_mailbox_id=b.root_mailbox_id AND l.body_object_id=b.object_id WHERE b.root_mailbox_id=?1 AND b.object_id=?2 AND b.record_id=?3 AND b.expired_local_ms IS NOT NULL AND l.expires_local_ms>?4)",
                params![root,object.to_string(),record.to_string(),time as i64],
                |r| r.get(0),
            )?;
            if !available {
                return Err(ReplicaError::NotFound);
            }
            let existing: bool = db.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM message_requests WHERE root_mailbox_id=?1 AND body_object_id=?2 AND requester_identity=?3)",
                params![root,object.to_string(),identity.to_string()],
                |r| r.get(0),
            )?;
            ensure_metadata_room(
                &db.connection,
                &root,
                if existing { 0 } else { METADATA_BYTES },
            )?;
            db.connection.execute(
                "INSERT INTO message_requests VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(root_mailbox_id,body_object_id,requester_identity) DO UPDATE SET requested_local_ms=excluded.requested_local_ms,expires_local_ms=excluded.expires_local_ms,record_id=excluded.record_id",
                params![root,object.to_string(),record.to_string(),identity.to_string(),time as i64,time.saturating_add(REQUEST_LIFETIME_MS) as i64],
            )?;
            Ok(())
        }).await
    }

    pub async fn accept_message(
        &self,
        mailbox: MailboxId,
        identity: IdentityId,
        object: ObjectId,
        record: RecordId,
    ) -> Result<()> {
        self.call(move |db| {
            let time = now()?;
            sweep(&db.connection, time)?;
            let root = root(&db.connection, mailbox)?;
            let allowed: bool = db.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM message_bodies WHERE root_mailbox_id=?1 AND object_id=?2 AND record_id=?3 AND direct_peer=?4 AND expired_local_ms IS NULL)",
                params![root,object.to_string(),record.to_string(),identity.to_string()],
                |r| r.get(0),
            )?;
            if !allowed {
                return Err(ReplicaError::Unauthorized);
            }
            let tx = db.connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute(
                "INSERT OR REPLACE INTO message_acceptances VALUES(?1,?2,?3,?4,?5)",
                params![root,object.to_string(),identity.to_string(),time as i64,time.saturating_add(ACCEPTANCE_LIFETIME_MS) as i64],
            )?;
            remove_body(&tx,&root,&object.to_string(),time)?;
            tx.commit()?;
            maintenance::reclaim(&db.connection)?;
            Ok(())
        }).await
    }

    /// Called only after the Space service verifies a current owner's signature.
    pub async fn space_storage(&self, root: MailboxId, before_ms: u64) -> Result<SpaceStorage> {
        if before_ms > now()? {
            return Err(ReplicaError::Invalid);
        }
        self.call(move |db| usage(&db.connection, root, before_ms))
            .await
    }
    /// Atomic fixed-cutoff cleanup, scoped to one root. Tombstones stop repair and
    /// old backups from uploading the same ciphertext into any child of the Space.
    pub async fn prune_messages(&self, root: MailboxId, before_ms: u64) -> Result<SpaceStorage> {
        let time = now()?;
        if before_ms > time {
            return Err(ReplicaError::Invalid);
        }
        self.call(move |db| {
            db.connection.pragma_update(None,"secure_delete","ON")?;
            let tx = db.connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let result = usage(&tx,root,before_ms)?;
            tx.execute(&format!("{TREE} INSERT OR IGNORE INTO pruned_objects(root_mailbox_id,object_id,pruned_local_ms) SELECT ?1,object_id,?3 FROM ({CANDIDATES})"),params![root.to_string(),before_ms as i64,time as i64])?;
            tx.execute(&format!("{TREE} DELETE FROM deliveries WHERE mailbox_id IN (SELECT id FROM tree) AND object_id IN (SELECT object_id FROM pruned_objects WHERE root_mailbox_id=?1)"),[root.to_string()])?;
            tx.execute("DELETE FROM objects WHERE NOT EXISTS(SELECT 1 FROM deliveries d WHERE d.object_id=objects.object_id)",[])?;
            tx.commit()?;
            maintenance::reclaim(&db.connection)?;
            Ok(result)
        }).await
    }
}
