use super::*;
use crate::{
    ids::{MailboxId, PeerId},
    replica::{InventoryEntry, TransferHint, VerifiedReceipt},
    sync::VerifiedChat,
};
#[derive(Clone, Debug)]
pub struct PeerCursor {
    pub storage_generation: String,
    pub arrival_seq: u64,
}
#[derive(Clone, Debug)]
pub struct InboxItem {
    pub peer: PeerId,
    pub mailbox: MailboxId,
    pub generation: String,
    pub seq: u64,
    pub object: ObjectId,
    pub epoch: i64,
}
impl ClientStore {
    pub(crate) async fn waiting_objects(&self, after: String) -> Result<Vec<(ObjectId, Vec<u8>)>> {
        self.call(move |c| {
            let mut q = c.prepare("SELECT object_id,ciphertext FROM objects WHERE object_id=(SELECT DISTINCT object_id FROM inbox WHERE state='WAITING_FOR_PROOF' AND object_id>?1 ORDER BY object_id LIMIT 1)")?;
            let values = q.query_map([after], |r| Ok((r.get::<_,String>(0)?,r.get::<_,Vec<u8>>(1)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
            values.into_iter().map(|(id, bytes)| Ok((id.parse().map_err(|_| StoreError::ObjectIntegrity)?,bytes))).collect()
        }).await
    }
    pub async fn confirm_stored(
        &self,
        attempt: DeliveryAttempt,
        receipt: VerifiedReceipt,
    ) -> Result<()> {
        self.confirm_stored_with_status(attempt, receipt, None)
            .await
    }
    pub(crate) async fn confirm_stored_with_status(
        &self,
        attempt: DeliveryAttempt,
        receipt: VerifiedReceipt,
        http_status: Option<u16>,
    ) -> Result<()> {
        let body = receipt.body();
        if body.peer_id != attempt.target.peer_id
            || body.mailbox_id != attempt.target.mailbox_id
            || body.object_id != attempt.object_id
        {
            return Err(StoreError::InvalidInput("receipt target mismatch"));
        }
        self.call(move|c|{let tx=c.transaction_with_behavior(TransactionBehavior::Immediate)?;let changed=tx.execute("UPDATE outbox SET state='STORED',receipt_record=?1,last_error_code=NULL WHERE object_id=?2 AND peer_id=?3 AND mailbox_id=?4 AND state='INFLIGHT' AND attempts=?5",params![receipt.bytes(),attempt.object_id.to_string(),attempt.target.peer_id.to_string(),attempt.target.mailbox_id.to_string(),attempt.number])?;if changed!=1{return Err(StoreError::StaleAttempt);}
        let kind:String=tx.query_row("SELECT kind FROM records WHERE record_id=?1",[attempt.record_id.to_string()],|r|r.get(0))?;
        let body=receipt.body();
        super::repair::remember_copy(&tx,body.peer_id,body.mailbox_id,&InventoryEntry{arrival_seq:body.arrival_seq,object_id:body.object_id,size_bytes:body.size_bytes,transfer_hint:if kind=="file.body"{TransferHint::Lazy}else{TransferHint::Eager}})?;
        tx.execute("UPDATE replica_copies SET receipt_record=?1,missing=0 WHERE peer_id=?2 AND mailbox_id=?3 AND object_id=?4",params![receipt.bytes(),body.peer_id.to_string(),body.mailbox_id.to_string(),body.object_id.to_string()])?;
        let mut event=audit::Event::new("STORED",Some(attempt.target));event.attempt=Some(attempt.number);event.http_status=http_status;
        audit::append(&tx,attempt.record_id,audit::clock()?,&event)?;
        if kind=="chat.message" { let time=audit::clock()?.as_millis();tx.execute("INSERT OR IGNORE INTO notification_outbox(record_id,object_id,created_local_ms,next_local_ms) VALUES(?,?,?,?)",params![attempt.record_id.to_string(),attempt.object_id.to_string(),time,time])?; }
        tx.commit()?;Ok(())}).await
    }
    pub async fn cursor(&self, peer: PeerId, mailbox: MailboxId) -> Result<Option<PeerCursor>> {
        self.call(move|c|Ok(c.query_row("SELECT storage_generation,arrival_seq FROM peer_cursors WHERE peer_id=?1 AND mailbox_id=?2",params![peer.to_string(),mailbox.to_string()],|r|Ok(PeerCursor{storage_generation:r.get(0)?,arrival_seq:r.get::<_,i64>(1)? as u64})).optional()?)).await
    }
    pub async fn stage_inbox(
        &self,
        peer: PeerId,
        mailbox: MailboxId,
        generation: String,
        entry: InventoryEntry,
        bytes: Option<Vec<u8>>,
        now: LocalTime,
    ) -> Result<()> {
        crate::record::hex::<32>(&generation)
            .map_err(|_| StoreError::InvalidInput("invalid storage generation"))?;
        if entry.arrival_seq == 0 || entry.arrival_seq > crate::record::MAX_INTEGER {
            return Err(StoreError::InvalidInput("invalid arrival sequence"));
        }
        let state = if entry.transfer_hint == TransferHint::Lazy {
            "DEFERRED"
        } else if bytes.is_some() {
            "PENDING"
        } else {
            "REJECTED"
        };
        self.call(move|c|{
   let tx=c.transaction_with_behavior(TransactionBehavior::Immediate)?;
   if let Some(bytes)=bytes {
    if bytes.is_empty()||bytes.len()>MAX_OBJECT_BYTES||bytes.len() as u64!=entry.size_bytes||ObjectId::of_ciphertext(&bytes)!=entry.object_id{return Err(StoreError::ObjectIntegrity);}
    if let Some(old)=get_object(&tx,entry.object_id)?{if old!=bytes{return Err(StoreError::ObjectIntegrity);}}else{tx.execute(INSERT_OBJECT,params![entry.object_id.to_string(),bytes,bytes.len() as i64,now.as_millis()])?;}
   }
   let epoch: i64 = tx.query_row("SELECT local_epoch FROM peer_cursors WHERE peer_id=?1 AND mailbox_id=?2",params![peer.to_string(),mailbox.to_string()],|r|r.get(0)).optional()?.unwrap_or(0);
   super::repair::remember_copy(&tx, peer, mailbox, &entry)?;
   let old:Option<(String,String)>=tx.query_row("SELECT object_id,transfer_hint FROM inbox WHERE peer_id=?1 AND mailbox_id=?2 AND storage_generation=?3 AND arrival_seq=?4 AND local_epoch=?5",params![peer.to_string(),mailbox.to_string(),generation,entry.arrival_seq as i64,epoch],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
   if old.as_ref().is_some_and(|o|o!=&(entry.object_id.to_string(),entry.transfer_hint.as_str().into())) {return Err(StoreError::ObjectIntegrity);}
   tx.execute("INSERT INTO inbox VALUES(?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT DO NOTHING",params![peer.to_string(),mailbox.to_string(),generation,entry.arrival_seq as i64,entry.object_id.to_string(),entry.transfer_hint.as_str(),state,epoch])?;
   tx.execute("INSERT INTO peer_cursors(peer_id,mailbox_id,storage_generation,arrival_seq) VALUES(?1,?2,?3,?4) ON CONFLICT(peer_id,mailbox_id) DO UPDATE SET storage_generation=excluded.storage_generation,arrival_seq=CASE WHEN peer_cursors.storage_generation=excluded.storage_generation THEN max(peer_cursors.arrival_seq,excluded.arrival_seq) ELSE excluded.arrival_seq END",params![peer.to_string(),mailbox.to_string(),generation,entry.arrival_seq as i64])?;
   tx.commit()?;Ok(())
  }).await
    }
    pub async fn pending_inbox(&self, limit: usize) -> Result<Vec<InboxItem>> {
        if !(1..=128).contains(&limit) {
            return Err(StoreError::InvalidInput("inbox limit"));
        }
        self.call(move|c|{let mut q=c.prepare("SELECT peer_id,mailbox_id,storage_generation,arrival_seq,object_id,local_epoch FROM inbox WHERE state='PENDING' ORDER BY peer_id,mailbox_id,arrival_seq LIMIT ?1")?;let rows=q.query_map([limit as i64],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,i64>(3)?,r.get::<_,String>(4)?,r.get::<_,i64>(5)?)))?;let mut items=Vec::new();for row in rows{let(p,m,g,s,o,e)=row?;items.push(InboxItem{peer:p.parse()?,mailbox:m.parse()?,generation:g,seq:s as u64,object:o.parse()?,epoch:e});}Ok(items)}).await
    }
    pub async fn finish_inbox(
        &self,
        item: InboxItem,
        verified: Option<VerifiedChat>,
        now: LocalTime,
    ) -> Result<()> {
        self.call(move|c|{let tx=c.transaction_with_behavior(TransactionBehavior::Immediate)?;
   if let Some(v)=&verified {
    let chat=v.chat();let id=v.record().id();
    tx.execute("INSERT INTO records VALUES(?1,?6,?2,?3,?4,'ACCEPTED',?5) ON CONFLICT(record_id) DO NOTHING",params![id.to_string(),chat.space_id.to_string(),chat.stream_id.to_string(),chat.config_id.to_string(),now.as_millis(),chat.kind])?;
    let inserted=tx.execute("INSERT INTO record_sources VALUES(?1,?2,-1) ON CONFLICT DO NOTHING",params![id.to_string(),item.object.to_string()])?;
    if inserted>0 { audit::append(&tx,id,now,&audit::Event::new("RECEIVED",Some(DeliveryTarget{peer_id:item.peer,mailbox_id:item.mailbox})))?; }
    if chat.kind=="chat.locator" {
     let locator=chat.locator.as_ref().ok_or(StoreError::InvalidInput("missing message locator"))?;
     tx.execute("INSERT INTO message_locators(locator_record_id,message_record_id,body_object_id) VALUES(?1,?2,?3) ON CONFLICT(locator_record_id) DO NOTHING",params![id.to_string(),locator.message_record_id.to_string(),locator.body_object_id.to_string()])?;
    }
   }
   tx.execute("UPDATE inbox SET state=?1 WHERE peer_id=?2 AND mailbox_id=?3 AND storage_generation=?4 AND arrival_seq=?5 AND local_epoch=?6 AND state='PENDING'",params![if verified.is_some(){"ACCEPTED"}else{"REJECTED"},item.peer.to_string(),item.mailbox.to_string(),item.generation,item.seq as i64,item.epoch])?;
   tx.commit()?;Ok(())}).await
    }

    pub async fn remember_local_locator(
        &self,
        locator: RecordId,
        message: RecordId,
        body: ObjectId,
    ) -> Result<()> {
        self.call(move |c| {
            c.execute(
                "INSERT INTO message_locators(locator_record_id,message_record_id,body_object_id) VALUES(?1,?2,?3) ON CONFLICT(locator_record_id) DO NOTHING",
                params![locator.to_string(),message.to_string(),body.to_string()],
            )?;
            Ok(())
        }).await
    }
    pub async fn message_sources(&self) -> Result<Vec<ObjectId>> {
        self.call(|c|{let mut q=c.prepare("SELECT DISTINCT s.object_id FROM record_sources s JOIN records r USING(record_id) WHERE r.kind IN ('chat.message','chat.action') AND r.status IN ('LOCAL','ACCEPTED') ORDER BY s.object_id")?;let values=q.query_map([],|r|r.get::<_,String>(0))?;let mut ids=Vec::new();for value in values{ids.push(value?.parse()?);}Ok(ids)}).await
    }
}

pub(crate) struct ConfigurationState {
    pub expected_head: Option<RecordId>,
    pub expected_snapshot: Option<ObjectId>,
    pub head: RecordId,
    pub sequence: u64,
    pub forked: bool,
    pub snapshot: Vec<u8>,
}
impl ClientStore {
    pub(crate) async fn commit_configuration(
        &self,
        input: PreparedLocalRecord,
        state: ConfigurationState,
        invite: Option<(RecordId, RecordId)>,
    ) -> Result<()> {
        self.call(move |c| {
            let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let space = input.metadata.space_id().ok_or(StoreError::InvalidInput("missing space"))?.to_string();
            let stream = input.metadata.stream_id().ok_or(StoreError::InvalidInput("missing stream"))?.to_string();
            let head: Option<String> = tx.query_row("SELECT config_id FROM stream_heads WHERE space_id=?1 AND stream_id=?2", params![space, stream], |r| r.get(0)).optional()?;
            let previous: Option<Vec<u8>> = tx.query_row("SELECT ciphertext FROM authority_snapshots WHERE space_id=?1 AND stream_id=?2", params![space, stream], |r| r.get(0)).optional()?;
            if head != state.expected_head.map(|id| id.to_string())
                || previous.as_deref().map(ObjectId::of_ciphertext) != state.expected_snapshot {
                return Err(StoreError::IdempotencyConflict("CONFIG_CONFLICT"));
            }
            write_local_rows(&tx, &input)?;
            if let Some((invite, request)) = invite {
                tx.execute("INSERT INTO used_invites VALUES(?1,?2,?3)", params![invite.to_string(), request.to_string(), input.record_id.to_string()])?;
            }
            tx.execute("INSERT INTO stream_heads VALUES(?1,?2,?3,?4,?5) ON CONFLICT(space_id,stream_id) DO UPDATE SET config_id=excluded.config_id,config_sequence=excluded.config_sequence,state=excluded.state",
                params![space, stream, state.head.to_string(), state.sequence as i64, if state.forked { "FORKED" } else { "KNOWN" }])?;
            tx.execute("INSERT INTO authority_snapshots VALUES(?1,?2,?3) ON CONFLICT(space_id,stream_id) DO UPDATE SET ciphertext=excluded.ciphertext", params![space, stream, state.snapshot])?;
            let held={
                let mut q=tx.prepare("SELECT DISTINCT o.record_id FROM outbox o JOIN records r USING(record_id) WHERE o.state IN ('PENDING','INFLIGHT') AND r.space_id=?1 AND r.stream_id=?2 AND (?4 OR r.config_id!=?3)")?;
                q.query_map(params![space,stream,state.head.to_string(),state.forked],|r|r.get::<_,String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?
            };
            tx.execute("UPDATE outbox SET state='HELD_STALE_CONFIG' WHERE state IN ('PENDING','INFLIGHT') AND record_id IN (SELECT record_id FROM records WHERE space_id=?1 AND stream_id=?2 AND (?4 OR config_id!=?3))", params![space, stream, state.head.to_string(), state.forked])?;
            for id in held { audit::append(&tx,id.parse()?,audit::clock()?,&audit::Event::new("HELD",None))?; }
            tx.execute("UPDATE inbox SET state='PENDING' WHERE state='WAITING_FOR_PROOF'", [])?;
            tx.commit()?;
            Ok(())
        }).await
    }
    pub async fn authority_snapshot(
        &self,
        space: crate::ids::SpaceId,
        stream: crate::ids::StreamId,
    ) -> Result<Option<Vec<u8>>> {
        self.call(move |c| {
            Ok(c.query_row(
                "SELECT ciphertext FROM authority_snapshots WHERE space_id=?1 AND stream_id=?2",
                params![space.to_string(), stream.to_string()],
                |r| r.get(0),
            )
            .optional()?)
        })
        .await
    }
    pub async fn previously_accepted(&self, id: RecordId) -> Result<bool> {
        self.call(move|c|Ok(c.query_row("SELECT EXISTS(SELECT 1 FROM records WHERE record_id=?1 AND status IN ('LOCAL','ACCEPTED'))",[id.to_string()],|r|r.get(0))?)).await
    }
    pub async fn defer_inbox(&self, item: InboxItem, stale: bool) -> Result<()> {
        self.call(move|c|{c.execute("UPDATE inbox SET state=?1 WHERE peer_id=?2 AND mailbox_id=?3 AND storage_generation=?4 AND arrival_seq=?5 AND local_epoch=?6 AND state='PENDING'",params![if stale{"QUARANTINED_STALE"}else{"WAITING_FOR_PROOF"},item.peer.to_string(),item.mailbox.to_string(),item.generation,item.seq as i64,item.epoch])?;Ok(())}).await
    }
}

impl ClientStore {
    pub async fn import_history(
        &self,
        bundle: crate::history::VerifiedBundle,
        now: LocalTime,
    ) -> Result<()> {
        self.call(move|c|{let tx=c.transaction_with_behavior(TransactionBehavior::Immediate)?;let object=bundle.object_id();
   if let Some(old)=get_object(&tx,object)?{if old!=bundle.ciphertext(){return Err(StoreError::ObjectIntegrity);}}else{tx.execute(INSERT_OBJECT,params![object.to_string(),bundle.ciphertext(),bundle.ciphertext().len() as i64,now.as_millis()])?;}
   let grant=bundle.grant();tx.execute("INSERT INTO records VALUES(?1,'history.access.granted',?2,?3,?4,'ACCEPTED',?5) ON CONFLICT DO NOTHING",params![bundle.record().id().to_string(),grant.space_id.to_string(),grant.stream_id.to_string(),grant.config_id.to_string(),now.as_millis()])?;
   tx.execute("INSERT INTO record_sources VALUES(?1,?2,-1) ON CONFLICT DO NOTHING",params![bundle.record().id().to_string(),object.to_string()])?;
   for (index,original) in bundle.originals().iter().enumerate(){let chat=original.chat().map_err(|_|StoreError::InvalidInput("invalid history original"))?;
    tx.execute("INSERT INTO records VALUES(?1,?6,?2,?3,?4,'ACCEPTED',?5) ON CONFLICT DO NOTHING",params![original.id().to_string(),chat.space_id.to_string(),chat.stream_id.to_string(),chat.config_id.to_string(),now.as_millis(),chat.kind])?;
    let inserted=tx.execute("INSERT INTO record_sources VALUES(?1,?2,?3) ON CONFLICT DO NOTHING",params![original.id().to_string(),object.to_string(),index as i64])?;
    if inserted>0 { audit::append(&tx,original.id(),now,&audit::Event::new("HISTORY_IMPORTED",None))?; }
   }tx.commit()?;Ok(())}).await
    }
}

impl ClientStore {
    pub async fn commit_file(
        &self,
        file: crate::files::PreparedFile,
        targets: Vec<DeliveryTarget>,
        now: LocalTime,
    ) -> Result<()> {
        let body: crate::files::FileBody = file
            .body
            .decode()
            .map_err(|_| StoreError::InvalidInput("file body"))?;
        let metadata = |kind| {
            RecordMetadata::new(
                kind,
                Some(body.space_id),
                Some(body.stream_id),
                Some(body.config_id),
            )
        };
        // Body is durable before the shared reference can be published. An unavailable
        // remote body remains an explicit download failure, never a fabricated file.
        self.commit_local_record_with_outbox(PreparedLocalRecord::new(
            file.body.id(),
            file.ciphertext,
            metadata("file.body")?,
            targets.clone(),
            now,
        )?)
        .await?;
        self.commit_local_record_with_outbox(PreparedLocalRecord::new(
            file.shared.id(),
            file.shared_ciphertext,
            metadata("file.shared")?,
            targets,
            now,
        )?)
        .await?;
        Ok(())
    }
    pub async fn commit_attachment_share(
        &self,
        file: crate::files::PreparedAttachmentShare,
        targets: Vec<DeliveryTarget>,
        now: LocalTime,
    ) -> Result<()> {
        let body: crate::files::FileShared = file
            .shared
            .decode()
            .map_err(|_| StoreError::InvalidInput("attachment descriptor"))?;
        if body.v != 1 || body.object_id.is_some() || body.attachment.is_none() {
            return Err(StoreError::InvalidInput("attachment descriptor"));
        }
        self.commit_local_record_with_outbox(PreparedLocalRecord::new(
            file.shared.id(),
            file.shared_ciphertext,
            RecordMetadata::new(
                "file.shared",
                Some(body.space_id),
                Some(body.stream_id),
                Some(body.config_id),
            )?,
            targets,
            now,
        )?)
        .await?;
        Ok(())
    }
    pub(crate) async fn finish_file_share(
        &self,
        item: InboxItem,
        verified: crate::files::VerifiedFileShare,
        now: LocalTime,
    ) -> Result<()> {
        self.call(move|c|{let tx=c.transaction_with_behavior(TransactionBehavior::Immediate)?;let b=verified.body();tx.execute("INSERT INTO records VALUES(?1,'file.shared',?2,?3,?4,'ACCEPTED',?5) ON CONFLICT DO NOTHING",params![verified.record().id().to_string(),b.space_id.to_string(),b.stream_id.to_string(),b.config_id.to_string(),now.as_millis()])?;tx.execute("INSERT INTO record_sources VALUES(?1,?2,-1) ON CONFLICT DO NOTHING",params![verified.record().id().to_string(),item.object.to_string()])?;tx.execute("UPDATE inbox SET state='ACCEPTED' WHERE peer_id=?1 AND mailbox_id=?2 AND storage_generation=?3 AND arrival_seq=?4 AND local_epoch=?5",params![item.peer.to_string(),item.mailbox.to_string(),item.generation,item.seq as i64,item.epoch])?;tx.commit()?;Ok(())}).await
    }
}

#[derive(Clone)]
pub struct DisplaySource {
    pub record: RecordId,
    pub object: ObjectId,
    pub index: i64,
    pub status: String,
}
impl ClientStore {
    pub async fn display_sources(
        &self,
        space: crate::ids::SpaceId,
        stream: crate::ids::StreamId,
    ) -> Result<Vec<DisplaySource>> {
        self.call(move |c| {
            // Projection only: do not rewrite record status, signed bytes or outbox state.
            // A local record without a target is not queued. One receipt cannot finish
            // a multi-target delivery, and faults must remain visible ahead of progress.
            let mut q = c.prepare(
                "SELECT r.record_id, s.object_id, s.source_index,
                 CASE
                   WHEN EXISTS(SELECT 1 FROM outbox o WHERE o.record_id=r.record_id AND o.state='REJECTED' AND COALESCE(o.last_error_code,'')!='REMOTE_PRUNED') THEN 'REJECTED'
                   WHEN EXISTS(SELECT 1 FROM outbox o WHERE o.record_id=r.record_id AND o.state='HELD_STALE_CONFIG') THEN 'HELD_STALE_CONFIG'
                   WHEN EXISTS(SELECT 1 FROM replica_copies c JOIN outbox o USING(peer_id,mailbox_id,object_id) WHERE o.record_id=r.record_id AND c.missing=1 AND c.pruned_record IS NULL) THEN 'REPAIR_PENDING'
                   WHEN EXISTS(SELECT 1 FROM outbox o WHERE o.record_id=r.record_id AND o.state IN ('PENDING','INFLIGHT')) THEN 'QUEUED'
                   WHEN EXISTS(SELECT 1 FROM outbox o WHERE o.record_id=r.record_id) AND NOT EXISTS(SELECT 1 FROM outbox o WHERE o.record_id=r.record_id AND o.state!='STORED') THEN 'STORED'
                   ELSE r.status
                 END
                 FROM records r JOIN record_sources s USING(record_id)
                 WHERE r.space_id=?1 AND r.stream_id=?2 AND r.kind IN ('chat.message','chat.locator','file.shared') AND r.status IN ('LOCAL','ACCEPTED')
                   AND (r.kind!='chat.locator' OR NOT EXISTS(
                     SELECT 1 FROM message_locators l
                     JOIN records m ON m.record_id=l.message_record_id AND m.status IN ('LOCAL','ACCEPTED')
                     WHERE l.locator_record_id=r.record_id
                   ))
                 ORDER BY r.first_seen_local_ms DESC,r.record_id,s.source_index LIMIT 1000"
            )?;
            let mut rows = q.query(params![space.to_string(),stream.to_string()])?;
            let mut out = Vec::new();
            while let Some(r) = rows.next()? { out.push(DisplaySource { record:r.get::<_,String>(0)?.parse()?,object:r.get::<_,String>(1)?.parse()?,index:r.get(2)?,status:r.get(3)? }); }
            Ok(out)
        }).await
    }
    pub(crate) async fn action_sources(
        &self,
        space: crate::ids::SpaceId,
        stream: crate::ids::StreamId,
        target: Option<RecordId>,
    ) -> Result<Vec<DisplaySource>> {
        self.call(move |c| {
            let mut q = c.prepare("SELECT r.record_id,s.object_id,s.source_index,r.status FROM records r JOIN record_sources s USING(record_id) WHERE r.space_id=?1 AND r.stream_id=?2 AND r.status IN ('LOCAL','ACCEPTED') AND ((?3 IS NULL AND r.kind='chat.action') OR (r.record_id=?3 AND r.kind IN ('chat.message','chat.locator','file.shared'))) ORDER BY r.record_id,s.source_index")?;
            let mut rows = q.query(params![space.to_string(),stream.to_string(),target.map(|id|id.to_string())])?;
            let mut result=Vec::new();
            while let Some(r)=rows.next()? { result.push(DisplaySource {record:r.get::<_,String>(0)?.parse()?,object:r.get::<_,String>(1)?.parse()?,index:r.get(2)?,status:r.get(3)?}); }
            Ok(result)
        }).await
    }
    pub async fn inbox_states(&self) -> Result<std::collections::BTreeMap<String, u64>> {
        self.call(|c| {
            let mut q = c.prepare("SELECT state,count(*) FROM inbox GROUP BY state")?;
            let mut rows = q.query([])?;
            let mut out = std::collections::BTreeMap::new();
            while let Some(r) = rows.next()? {
                out.insert(r.get(0)?, read_count(r, 1)?);
            }
            Ok(out)
        })
        .await
    }
    pub async fn deferred_object_size(&self, object: ObjectId) -> Result<Option<u64>> {
        // The signed metadata determines object ID; inventory size is only a transfer bound.
        self.call(move |c| {
            Ok(c.query_row(
                "SELECT size_bytes FROM objects WHERE object_id=?1",
                [object.to_string()],
                |r| read_count(r, 0),
            )
            .optional()?)
        })
        .await
    }
}

impl ClientStore {
    pub(crate) async fn reset_peer_cursor(
        &self,
        peer: PeerId,
        mailbox: MailboxId,
        generation: String,
    ) -> Result<()> {
        crate::record::hex::<32>(&generation)
            .map_err(|_| StoreError::InvalidInput("invalid storage generation"))?;
        self.call(move |c|{
            let tx=c.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute("INSERT INTO peer_cursors(peer_id,mailbox_id,storage_generation,arrival_seq) VALUES(?1,?2,?3,0) ON CONFLICT(peer_id,mailbox_id) DO UPDATE SET storage_generation=excluded.storage_generation,arrival_seq=0,local_epoch=local_epoch+1",params![peer.to_string(),mailbox.to_string(),generation])?;
            tx.execute("UPDATE replica_scans SET storage_generation=?3,round=round+1,after_seq=0,head=0,complete=0 WHERE peer_id=?1 AND mailbox_id=?2",params![peer.to_string(),mailbox.to_string(),generation])?;
            tx.commit()?;
            Ok(())
        }).await
    }
}

#[cfg(test)]
mod cursor_tests {
    use super::*;
    #[tokio::test]
    async fn reset_of_an_empty_generation_is_durable_and_preserves_pending_objects() {
        let directory = tempfile::tempdir().unwrap();
        let store = ClientStore::open(directory.path()).await.unwrap();
        let peer = PeerId::from_bytes([1; 32]);
        let mailbox = MailboxId::from_bytes([2; 32]);
        let first = "03".repeat(32);
        let second = "04".repeat(32);
        let bytes = b"PUBLIC TRANSFER PLACEHOLDER".to_vec();
        let object = ObjectId::of_ciphertext(&bytes);
        store
            .stage_inbox(
                peer,
                mailbox,
                first,
                InventoryEntry {
                    arrival_seq: 7,
                    object_id: object,
                    size_bytes: bytes.len() as u64,
                    transfer_hint: TransferHint::Eager,
                },
                Some(bytes.clone()),
                LocalTime::from_millis(1).unwrap(),
            )
            .await
            .unwrap();
        store
            .reset_peer_cursor(peer, mailbox, second.clone())
            .await
            .unwrap();
        store.close().await.unwrap();
        let store = ClientStore::open(directory.path()).await.unwrap();
        let cursor = store.cursor(peer, mailbox).await.unwrap().unwrap();
        assert_eq!(cursor.storage_generation, second);
        assert_eq!(cursor.arrival_seq, 0);
        assert_eq!(store.get_object(object).await.unwrap(), Some(bytes));
        assert_eq!(store.pending_inbox(128).await.unwrap().len(), 1);
        store.close().await.unwrap();
    }
}
