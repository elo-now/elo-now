//! Device-local history floors. Signed clocks are a display policy, never proof
//! of authorship time. Known record/object IDs remain denied regardless of time.
use super::*;
use crate::ids::{SpaceId, StreamId};

#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub(crate) struct LocalChatState {
    pub hidden: bool,
    pub generation: u64,
}

pub(super) fn deleted_record(db: &Connection, id: RecordId) -> Result<bool> {
    Ok(db.query_row(
        "SELECT EXISTS(SELECT 1 FROM local_deleted_records WHERE record_id=?1)",
        [id.to_string()],
        |r| r.get(0),
    )?)
}

pub(super) fn deleted_object(db: &Connection, id: ObjectId) -> Result<bool> {
    Ok(db.query_row(
        "SELECT EXISTS(SELECT 1 FROM local_deleted_objects WHERE object_id=?1)",
        [id.to_string()],
        |r| r.get(0),
    )?)
}

pub(super) fn deleted_target(
    db: &Connection,
    space: &str,
    stream: &str,
    id: RecordId,
) -> Result<bool> {
    Ok(db.query_row("SELECT EXISTS(SELECT 1 FROM local_deleted_targets WHERE space_id=?1 AND stream_id=?2 AND record_id=?3)", params![space,stream,id.to_string()], |row| row.get(0))?)
}

pub(super) fn rejects(db: &Connection, record: &crate::record::SignedRecord) -> Result<bool> {
    if deleted_record(db, record.id())? {
        return Ok(true);
    }
    let body = record.body();
    if !matches!(
        body["kind"].as_str(),
        Some("chat.message" | "chat.action" | "chat.locator" | "file.shared" | "file.body")
    ) {
        return Ok(false);
    }
    let (Some(space), Some(stream)) = (body["space_id"].as_str(), body["stream_id"].as_str())
    else {
        return Ok(false);
    };
    let cutoff: Option<i64> = db
        .query_row(
            "SELECT cutoff_ms FROM local_chat_deletions WHERE space_id=?1 AND stream_id=?2",
            params![space, stream],
            |r| r.get(0),
        )
        .optional()?;
    let Some(cutoff) = cutoff else {
        return Ok(false);
    };
    if deleted_target(db, space, stream, record.id())? {
        return Ok(true);
    }
    // Legacy file records have no signed time. They cannot establish that they
    // belong to the new history window after a local deletion.
    let time = body["logical_time"]
        .as_u64()
        .or_else(|| body["attachment"]["created_at_ms"].as_u64())
        .unwrap_or(0);
    let old_target = [
        body["locator"]["message_record_id"].as_str(),
        body["payload"]["action"]["target"].as_str(),
    ]
    .into_iter()
    .flatten()
    .filter_map(|id| id.parse().ok())
    .map(|id| Ok(deleted_record(db, id)? || deleted_target(db, space, stream, id)?))
    .collect::<Result<Vec<_>>>()?
    .into_iter()
    .any(|v| v);
    Ok(time <= cutoff as u64 || old_target)
}

pub(super) fn reveal(db: &Connection, space: SpaceId, stream: StreamId) -> Result<()> {
    db.execute(
        "UPDATE local_chat_deletions SET hidden=0 WHERE space_id=?1 AND stream_id=?2",
        params![space.to_string(), stream.to_string()],
    )?;
    Ok(())
}

pub(super) fn discard_object(db: &Connection, object: ObjectId) -> Result<()> {
    let has_authority: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM record_sources JOIN records USING(record_id) WHERE object_id=?1 AND kind NOT IN ('chat.message','chat.action','chat.locator','file.shared','file.body','history.access.granted'))", [object.to_string()], |r| r.get(0))?;
    if has_authority {
        return Err(StoreError::InvalidInput(
            "local removal cannot erase authority",
        ));
    }
    db.execute(
        "INSERT OR IGNORE INTO local_deleted_objects VALUES(?1)",
        [object.to_string()],
    )?;
    db.execute(
        "UPDATE inbox SET state='REJECTED' WHERE object_id=?1",
        [object.to_string()],
    )?;
    // A shared history object may already have been indexed. Keep only metadata
    // tombstones, never an encrypted envelope that still contains removed text.
    let records = {
        let mut q = db.prepare("SELECT record_id FROM record_sources WHERE object_id=?1")?;
        q.query_map([object.to_string()], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    for record in records {
        db.execute(
            "INSERT OR IGNORE INTO local_deleted_records VALUES(?1)",
            [&record],
        )?;
        for table in [
            "notification_outbox",
            "outbox",
            "message_audit",
            "record_sources",
        ] {
            db.execute(
                &format!("DELETE FROM {table} WHERE record_id=?1"),
                [&record],
            )?;
        }
        db.execute("DELETE FROM records WHERE record_id=?1", [&record])?;
    }
    for table in [
        "notification_outbox",
        "outbox",
        "record_sources",
        "replica_copies",
    ] {
        db.execute(
            &format!("DELETE FROM {table} WHERE object_id=?1"),
            [object.to_string()],
        )?;
    }
    db.execute(
        "DELETE FROM objects WHERE object_id=?1",
        [object.to_string()],
    )?;
    Ok(())
}

impl ClientStore {
    pub(crate) async fn local_file_share_sources(
        &self,
        space: SpaceId,
        stream: StreamId,
    ) -> Result<Vec<DisplaySource>> {
        self.call(move |db| {
            let mut q = db.prepare("SELECT r.record_id,s.object_id,s.source_index,r.status FROM records r JOIN record_sources s USING(record_id) WHERE r.space_id=?1 AND r.stream_id=?2 AND r.kind='file.shared' AND r.status IN ('LOCAL','ACCEPTED') ORDER BY r.record_id,s.source_index")?;
            let mut rows = q.query(params![space.to_string(),stream.to_string()])?;
            let mut result = Vec::new();
            while let Some(r) = rows.next()? {
                result.push(DisplaySource { record: r.get::<_,String>(0)?.parse()?, object: r.get::<_,String>(1)?.parse()?, index:r.get(2)?, status:r.get(3)? });
            }
            Ok(result)
        }).await
    }

    pub(crate) async fn discard_known_removed_inbox(
        &self,
        item: &InboxItem,
        record: RecordId,
    ) -> Result<bool> {
        let object = item.object;
        self.call(move |db| {
            if !deleted_record(db, record)? {
                return Ok(false);
            }
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            discard_object(&tx, object)?;
            tx.commit()?;
            Ok(true)
        })
        .await
    }
    pub(crate) async fn local_chat_state(
        &self,
        space: SpaceId,
        stream: StreamId,
    ) -> Result<LocalChatState> {
        self.call(move |db| Ok(db.query_row("SELECT hidden,generation FROM local_chat_deletions WHERE space_id=?1 AND stream_id=?2", params![space.to_string(), stream.to_string()], |r| Ok(LocalChatState { hidden: r.get(0)?, generation: r.get::<_, i64>(1)? as u64 })).optional()?.unwrap_or_default())).await
    }

    pub(crate) async fn local_deleted_records(
        &self,
        ids: Vec<RecordId>,
    ) -> Result<std::collections::BTreeSet<RecordId>> {
        self.call(move |db| {
            ids.into_iter()
                .filter_map(|id| match deleted_record(db, id) {
                    Ok(true) => Some(Ok(id)),
                    Ok(false) => None,
                    Err(error) => Some(Err(error)),
                })
                .collect()
        })
        .await
    }

    pub(crate) async fn reveal_local_chat(&self, space: SpaceId, stream: StreamId) -> Result<()> {
        self.call(move |db| reveal(db, space, stream)).await
    }

    pub(crate) async fn delete_chat_local(
        &self,
        space: SpaceId,
        stream: StreamId,
        now: LocalTime,
    ) -> Result<(LocalChatState, bool)> {
        self.delete_chat_local_with_objects(space, stream, now, Vec::new())
            .await
    }

    pub(crate) async fn delete_chat_local_with_objects(
        &self,
        space: SpaceId,
        stream: StreamId,
        now: LocalTime,
        verified_file_objects: Vec<ObjectId>,
    ) -> Result<(LocalChatState, bool)> {
        self.call(move |db| {
            db.pragma_update(None, "secure_delete", "ON")?;
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute("INSERT INTO local_chat_deletions VALUES(?1,?2,?3,1,1) ON CONFLICT(space_id,stream_id) DO UPDATE SET cutoff_ms=max(cutoff_ms,excluded.cutoff_ms),generation=generation+1,hidden=1", params![space.to_string(),stream.to_string(),now.as_millis()])?;
            let scope = "SELECT record_id FROM records WHERE space_id=?1 AND stream_id=?2 AND kind IN ('chat.message','chat.action','chat.locator','file.shared','file.body','history.access.granted')";
            // A locator may point at an unrelated object/record. Its missing
            // target is denied only after the received record proves this scope.
            tx.execute(&format!("INSERT OR IGNORE INTO local_deleted_targets SELECT ?1,?2,message_record_id FROM message_locators WHERE locator_record_id IN ({scope})"), params![space.to_string(),stream.to_string()])?;
            tx.execute(&format!("INSERT OR IGNORE INTO local_deleted_records {scope}"), params![space.to_string(),stream.to_string()])?;
            let objects = {
                let mut q = tx.prepare(&format!("SELECT DISTINCT object_id FROM record_sources WHERE record_id IN ({scope}) UNION SELECT object_id FROM objects JOIN local_deleted_objects USING(object_id)"))?;
                q.query_map(params![space.to_string(),stream.to_string()], |r| r.get::<_,String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?
            };
            for object in objects { discard_object(&tx, object.parse()?)?; }
            for object in verified_file_objects { discard_object(&tx, object)?; }
            let generation = tx.query_row("SELECT generation FROM local_chat_deletions WHERE space_id=?1 AND stream_id=?2", params![space.to_string(),stream.to_string()], |r| r.get::<_,i64>(0))? as u64;
            tx.commit()?;
            let cleanup_pending = db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);").is_err();
            Ok((LocalChatState { hidden: true, generation }, cleanup_pending))
        }).await
    }
}
