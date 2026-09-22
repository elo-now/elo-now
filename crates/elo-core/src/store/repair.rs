//! Durable, bounded reconciliation of copies at their previously observed targets.
use super::*;
use crate::{
    ids::{MailboxId, PeerId},
    replica::{Inventory, InventoryEntry, TransferHint, VerifiedReceipt},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ScanCursor {
    pub generation: String,
    pub round: i64,
    pub after: u64,
    pub head: u64,
    pub complete: bool,
}
impl ScanCursor {
    pub fn next_after(&self) -> u64 {
        if self.complete { 0 } else { self.after }
    }
}
pub(crate) struct RepairAttempt {
    pub target: DeliveryTarget,
    pub object: ObjectId,
    pub size: u64,
    pub hint: TransferHint,
    pub generation: String,
    pub number: i64,
}

fn scan(c: &Connection, peer: PeerId, mailbox: MailboxId) -> Result<Option<ScanCursor>> {
    Ok(c.query_row(
        "SELECT storage_generation,round,after_seq,head,complete FROM replica_scans WHERE peer_id=?1 AND mailbox_id=?2",
        params![peer.to_string(),mailbox.to_string()],
        |r| Ok(ScanCursor { generation:r.get(0)?,round:r.get(1)?,after:read_count(r,2)?,head:read_count(r,3)?,complete:r.get(4)? }),
    ).optional()?)
}
pub(super) fn remember_copy(
    c: &Connection,
    peer: PeerId,
    mailbox: MailboxId,
    entry: &InventoryEntry,
) -> Result<()> {
    if entry.size_bytes == 0 || entry.size_bytes > MAX_OBJECT_BYTES as u64 {
        return Err(StoreError::ObjectIntegrity);
    }
    let old: Option<(u64, String)> = c.query_row(
        "SELECT size_bytes,transfer_hint FROM replica_copies WHERE peer_id=?1 AND mailbox_id=?2 AND object_id=?3",
        params![peer.to_string(),mailbox.to_string(),entry.object_id.to_string()],
        |r|Ok((read_count(r,0)?,r.get(1)?)),
    ).optional()?;
    if old.is_some_and(|(size, hint)| {
        (size != 0 && size != entry.size_bytes) || hint != entry.transfer_hint.as_str()
    }) {
        return Err(StoreError::ObjectIntegrity);
    }
    c.execute(
        "INSERT INTO replica_copies(peer_id,mailbox_id,object_id,size_bytes,transfer_hint) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(peer_id,mailbox_id,object_id) DO UPDATE SET size_bytes=excluded.size_bytes",
        params![peer.to_string(),mailbox.to_string(),entry.object_id.to_string(),entry.size_bytes as i64,entry.transfer_hint.as_str()],
    )?;
    Ok(())
}
impl ClientStore {
    /// Preserve all local records/ciphertext while permanently stopping retries
    /// for this target. Only a proof verified against the pinned peer reaches here.
    pub(crate) async fn confirm_pruned(&self, proof: crate::replica::VerifiedPruned) -> Result<()> {
        self.call(move |c| {
            let target=DeliveryTarget {peer_id:proof.peer(),mailbox_id:proof.mailbox()};
            let tx=c.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute("INSERT INTO replica_copies(peer_id,mailbox_id,object_id,size_bytes,transfer_hint,pruned_record) VALUES(?1,?2,?3,0,'eager',?4) ON CONFLICT(peer_id,mailbox_id,object_id) DO UPDATE SET pruned_record=excluded.pruned_record,missing=0", params![proof.peer().to_string(),proof.mailbox().to_string(),proof.object().to_string(),proof.bytes()])?;
            tx.execute("UPDATE outbox SET state='REJECTED',last_error_code='REMOTE_PRUNED' WHERE peer_id=?1 AND mailbox_id=?2 AND object_id=?3",params![proof.peer().to_string(),proof.mailbox().to_string(),proof.object().to_string()])?;
            let mut event=audit::Event::new("REPAIR_FAILED",Some(target));
            event.failure=Some(TransportFailure::Http(410));
            audit::append_object(&tx,proof.object(),audit::clock()?,&event)?;
            tx.commit()?;
            Ok(())
        }).await
    }
    pub(crate) async fn inventory_reuses_sequence(
        &self,
        peer: PeerId,
        mailbox: MailboxId,
        page: Inventory,
    ) -> Result<bool> {
        self.call(move |c| {
            for entry in page.entries {
                let conflict:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM inbox i JOIN peer_cursors p USING(peer_id,mailbox_id,storage_generation,local_epoch) WHERE i.peer_id=?1 AND i.mailbox_id=?2 AND i.storage_generation=?3 AND i.arrival_seq=?4 AND i.object_id!=?5)",params![peer.to_string(),mailbox.to_string(),page.storage_generation,entry.arrival_seq as i64,entry.object_id.to_string()],|r|r.get(0))?;
                if conflict {return Ok(true);}
            }
            Ok(false)
        }).await
    }
    pub(crate) async fn inbox_entry_known(
        &self,
        peer: PeerId,
        mailbox: MailboxId,
        generation: String,
        entry: InventoryEntry,
    ) -> Result<bool> {
        self.call(move |c| Ok(c.query_row("SELECT EXISTS(SELECT 1 FROM inbox i JOIN peer_cursors p USING(peer_id,mailbox_id,storage_generation,local_epoch) WHERE i.peer_id=?1 AND i.mailbox_id=?2 AND i.storage_generation=?3 AND i.arrival_seq=?4 AND i.object_id=?5 AND i.transfer_hint=?6)",params![peer.to_string(),mailbox.to_string(),generation,entry.arrival_seq as i64,entry.object_id.to_string(),entry.transfer_hint.as_str()],|r|r.get(0))?)).await
    }
    pub(crate) async fn scan_cursor(
        &self,
        peer: PeerId,
        mailbox: MailboxId,
    ) -> Result<Option<ScanCursor>> {
        self.call(move |c| scan(c, peer, mailbox)).await
    }
    pub(crate) async fn begin_scan(
        &self,
        peer: PeerId,
        mailbox: MailboxId,
        expected: Option<ScanCursor>,
        generation: String,
        head: u64,
    ) -> Result<ScanCursor> {
        self.call(move |c| {
            let tx=c.transaction_with_behavior(TransactionBehavior::Immediate)?;
            if scan(&tx,peer,mailbox)? != expected { return Err(StoreError::StaleAttempt); }
            let (round,after)=match expected {
                Some(s) if !s.complete && s.generation==generation => (s.round,s.after),
                Some(s) => (s.round.checked_add(1).ok_or(StoreError::InvalidInput("scan counter exhausted"))?,0),
                None => (1,0),
            };
            tx.execute("INSERT INTO replica_scans VALUES(?1,?2,?3,?4,?5,?6,0) ON CONFLICT(peer_id,mailbox_id) DO UPDATE SET storage_generation=excluded.storage_generation,round=excluded.round,after_seq=excluded.after_seq,head=excluded.head,complete=0",
                params![peer.to_string(),mailbox.to_string(),generation,round,after as i64,head as i64])?;
            tx.commit()?;
            Ok(ScanCursor{generation,round,after,head,complete:false})
        }).await
    }
    pub(crate) async fn finish_scan_page(
        &self,
        peer: PeerId,
        mailbox: MailboxId,
        expected: ScanCursor,
        page: Inventory,
    ) -> Result<bool> {
        self.call(move |c| {
            let tx=c.transaction_with_behavior(TransactionBehavior::Immediate)?;
            if scan(&tx,peer,mailbox)?.as_ref()!=Some(&expected) || page.storage_generation!=expected.generation {
                return Err(StoreError::StaleAttempt);
            }
            for entry in &page.entries {
                remember_copy(&tx,peer,mailbox,entry)?;
                tx.execute("UPDATE replica_copies SET seen_round=?4,missing=0 WHERE peer_id=?1 AND mailbox_id=?2 AND object_id=?3",
                    params![peer.to_string(),mailbox.to_string(),entry.object_id.to_string(),expected.round])?;
            }
            let after=page.entries.last().map_or(expected.after,|e|e.arrival_seq);
            let complete=after>=page.head;
            if complete {
                tx.execute("UPDATE replica_copies SET missing=1 WHERE peer_id=?1 AND mailbox_id=?2 AND seen_round!=?3 AND pruned_record IS NULL",
                    params![peer.to_string(),mailbox.to_string(),expected.round])?;
            }
            tx.execute("UPDATE replica_scans SET after_seq=?3,head=?4,complete=?5 WHERE peer_id=?1 AND mailbox_id=?2",
                params![peer.to_string(),mailbox.to_string(),after as i64,page.head as i64,complete])?;
            tx.commit()?;
            Ok(complete)
        }).await
    }
    /// Scheduling is committed before HTTP. A lost response leaves a bounded retry.
    pub(crate) async fn claim_repair(
        &self,
        target: DeliveryTarget,
        now: LocalTime,
        jitter: u64,
    ) -> Result<Option<RepairAttempt>> {
        self.call(move |c| {
            let tx=c.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let row:Option<(String,u64,String,i64,String)>=tx.query_row(
                "SELECT c.object_id,c.size_bytes,c.transfer_hint,c.attempts,s.storage_generation FROM replica_copies c JOIN replica_scans s USING(peer_id,mailbox_id) WHERE c.peer_id=?1 AND c.mailbox_id=?2 AND c.missing=1 AND c.pruned_record IS NULL AND c.retention_expired=0 AND c.next_attempt_local_ms<=?3 ORDER BY c.next_attempt_local_ms,c.object_id LIMIT 1",
                params![target.peer_id.to_string(),target.mailbox_id.to_string(),now.as_millis()],
                |r|Ok((r.get(0)?,read_count(r,1)?,r.get(2)?,r.get(3)?,r.get(4)?)),
            ).optional()?;
            let Some((object,size,hint,attempts,generation))=row else { return Ok(None); };
            let number=attempts.checked_add(1).ok_or(StoreError::InvalidInput("repair counter exhausted"))?;
            let next=now.as_millis().saturating_add(crate::sync::retry_delay_ms(number as u64,jitter) as i64);
            tx.execute("UPDATE replica_copies SET attempts=?4,next_attempt_local_ms=?5 WHERE peer_id=?1 AND mailbox_id=?2 AND object_id=?3",
                params![target.peer_id.to_string(),target.mailbox_id.to_string(),object,number,next])?;
            let mut event=audit::Event::new("REPAIR_STARTED",Some(target));event.attempt=Some(number);
            audit::append_object(&tx,object.parse()?,now,&event)?;
            tx.commit()?;
            Ok(Some(RepairAttempt{target,object:object.parse()?,size,hint:if hint=="lazy"{TransferHint::Lazy}else{TransferHint::Eager},generation,number}))
        }).await
    }

    pub(crate) async fn suspend_expired_copy(&self, attempt: RepairAttempt) -> Result<()> {
        self.call(move |c| {
            c.execute(
                "UPDATE replica_copies SET retention_expired=1 WHERE peer_id=?1 AND mailbox_id=?2 AND object_id=?3 AND missing=1 AND attempts=?4",
                params![attempt.target.peer_id.to_string(),attempt.target.mailbox_id.to_string(),attempt.object.to_string(),attempt.number],
            )?;
            Ok(())
        }).await
    }

    pub(crate) async fn resume_requested_copies(
        &self,
        peer: PeerId,
        mailbox: MailboxId,
        objects: Vec<ObjectId>,
    ) -> Result<()> {
        self.call(move |c| {
            let tx=c.transaction_with_behavior(TransactionBehavior::Immediate)?;
            for object in objects {
                tx.execute(
                    "UPDATE replica_copies SET retention_expired=0,attempts=0,next_attempt_local_ms=0 WHERE peer_id=?1 AND mailbox_id=?2 AND object_id=?3 AND missing=1 AND pruned_record IS NULL",
                    params![peer.to_string(),mailbox.to_string(),object.to_string()],
                )?;
            }
            tx.commit()?;
            Ok(())
        }).await
    }
    pub(crate) async fn copy_sources(
        &self,
        object: ObjectId,
    ) -> Result<Vec<(DeliveryTarget, u64)>> {
        self.call(move |c| {
            let mut q=c.prepare("SELECT peer_id,mailbox_id,size_bytes FROM replica_copies WHERE object_id=?1 AND size_bytes>0 AND pruned_record IS NULL ORDER BY missing,peer_id,mailbox_id LIMIT 128")?;
            let mut rows=q.query([object.to_string()])?;
            let mut out=Vec::new();
            while let Some(r)=rows.next()? { out.push((DeliveryTarget{peer_id:r.get::<_,String>(0)?.parse()?,mailbox_id:r.get::<_,String>(1)?.parse()?},read_count(r,2)?)); }
            Ok(out)
        }).await
    }
    pub(crate) async fn cache_repair_object(
        &self,
        object: ObjectId,
        bytes: Vec<u8>,
        now: LocalTime,
    ) -> Result<()> {
        self.call(move |c| {
            if bytes.is_empty()
                || bytes.len() > MAX_OBJECT_BYTES
                || ObjectId::of_ciphertext(&bytes) != object
            {
                return Err(StoreError::ObjectIntegrity);
            }
            c.execute(
                "INSERT INTO objects VALUES(?1,?2,?3,?4) ON CONFLICT DO NOTHING",
                params![
                    object.to_string(),
                    bytes,
                    bytes.len() as i64,
                    now.as_millis()
                ],
            )?;
            Ok(())
        })
        .await
    }
    pub(crate) async fn confirm_repair(
        &self,
        attempt: RepairAttempt,
        receipt: VerifiedReceipt,
    ) -> Result<()> {
        let b = receipt.body();
        if b.peer_id != attempt.target.peer_id
            || b.mailbox_id != attempt.target.mailbox_id
            || b.object_id != attempt.object
            || b.storage_generation != attempt.generation
        {
            return Err(StoreError::InvalidInput(
                "repair receipt target or generation mismatch",
            ));
        }
        self.call(move |c| {
            let tx=c.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let changed=tx.execute("UPDATE replica_copies SET missing=0,receipt_record=?4 WHERE peer_id=?1 AND mailbox_id=?2 AND object_id=?3 AND missing=1 AND pruned_record IS NULL AND attempts=?5 AND EXISTS(SELECT 1 FROM replica_scans s WHERE s.peer_id=?1 AND s.mailbox_id=?2 AND s.storage_generation=?6)",
                params![attempt.target.peer_id.to_string(),attempt.target.mailbox_id.to_string(),attempt.object.to_string(),receipt.bytes(),attempt.number,attempt.generation])?;
            if changed!=1 { return Err(StoreError::StaleAttempt); }
            tx.execute("UPDATE outbox SET receipt_record=?4 WHERE peer_id=?1 AND mailbox_id=?2 AND object_id=?3 AND state='STORED'",
                params![attempt.target.peer_id.to_string(),attempt.target.mailbox_id.to_string(),attempt.object.to_string(),receipt.bytes()])?;
            let mut event=audit::Event::new("REPAIRED",Some(attempt.target));event.attempt=Some(attempt.number);
            audit::append_object(&tx,attempt.object,audit::clock()?,&event)?;
            tx.commit()?;
            Ok(())
        }).await
    }
    pub async fn missing_copies(&self) -> Result<u64> {
        self.call(|c| {
            Ok(c.query_row(
                "SELECT count(*) FROM replica_copies WHERE missing=1 AND pruned_record IS NULL",
                [],
                |r| read_count(r, 0),
            )?)
        })
        .await
    }

    pub(crate) async fn audit_repair_failure(
        &self,
        object: ObjectId,
        target: DeliveryTarget,
        attempt: i64,
        failure: TransportFailure,
    ) -> Result<()> {
        self.call(move |c| {
            let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let mut event = audit::Event::new("REPAIR_FAILED", Some(target));
            event.attempt = Some(attempt);
            event.failure = Some(failure);
            audit::append_object(&tx, object, audit::clock()?, &event)?;
            tx.commit()?;
            Ok(())
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn time(n: u64) -> LocalTime {
        LocalTime::from_millis(n).unwrap()
    }
    #[tokio::test]
    async fn failed_scan_commit_is_atomic_and_retry_schedule_survives_restart() {
        let dir = tempfile::tempdir().unwrap();
        let store = ClientStore::open(dir.path()).await.unwrap();
        let peer = PeerId::from_bytes([1; 32]);
        let mailbox = MailboxId::from_bytes([2; 32]);
        let generation = "03".repeat(32);
        let bytes = b"PUBLIC DURABILITY FIXTURE".to_vec();
        let entry = InventoryEntry {
            arrival_seq: 1,
            object_id: ObjectId::of_ciphertext(&bytes),
            size_bytes: bytes.len() as u64,
            transfer_hint: TransferHint::Eager,
        };
        store
            .stage_inbox(
                peer,
                mailbox,
                generation.clone(),
                entry.clone(),
                Some(bytes.clone()),
                time(1),
            )
            .await
            .unwrap();
        let cursor = store
            .begin_scan(peer, mailbox, None, generation.clone(), 1)
            .await
            .unwrap();
        let page = Inventory {
            storage_generation: generation.clone(),
            head: 1,
            entries: vec![entry],
            requested_messages: vec![],
        };
        assert!(
            store
                .finish_scan_page(peer, mailbox, cursor, page)
                .await
                .unwrap()
        );
        store
            .reset_peer_cursor(peer, mailbox, generation.clone())
            .await
            .unwrap();
        let cursor = store.scan_cursor(peer, mailbox).await.unwrap().unwrap();
        let empty = Inventory {
            storage_generation: generation.clone(),
            head: 0,
            entries: vec![],
            requested_messages: vec![],
        };
        let raw = Connection::open(dir.path().join("client.sqlite")).unwrap();
        raw.execute_batch("CREATE TRIGGER fail_scan BEFORE UPDATE ON replica_scans BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
        assert!(
            store
                .finish_scan_page(peer, mailbox, cursor.clone(), empty.clone())
                .await
                .is_err()
        );
        assert_eq!(store.missing_copies().await.unwrap(), 0);
        assert_eq!(
            store.scan_cursor(peer, mailbox).await.unwrap(),
            Some(cursor.clone())
        );
        assert_eq!(store.pending_inbox(128).await.unwrap().len(), 1);
        raw.execute_batch("DROP TRIGGER fail_scan").unwrap();
        store.close().await.unwrap();
        let store = ClientStore::open(dir.path()).await.unwrap();
        assert!(
            store
                .finish_scan_page(peer, mailbox, cursor, empty)
                .await
                .unwrap()
        );
        assert_eq!(store.missing_copies().await.unwrap(), 1);
        let target = DeliveryTarget {
            peer_id: peer,
            mailbox_id: mailbox,
        };
        assert_eq!(
            store
                .claim_repair(target, time(100), 0)
                .await
                .unwrap()
                .unwrap()
                .number,
            1
        );
        store.close().await.unwrap();
        let store = ClientStore::open(dir.path()).await.unwrap();
        assert!(
            store
                .claim_repair(target, time(1099), 0)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store
                .claim_repair(target, time(1100), 0)
                .await
                .unwrap()
                .unwrap()
                .number,
            2
        );
        assert_eq!(
            store
                .get_object(ObjectId::of_ciphertext(&bytes))
                .await
                .unwrap(),
            Some(bytes)
        );
        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn repair_receipt_requires_current_generation_and_atomic_nonstale_commit() {
        let remote = tempfile::tempdir().unwrap();
        let replica = crate::replica::ReplicaStore::open(remote.path())
            .await
            .unwrap();
        let mailbox = replica.create_mailbox(4096).await.unwrap();
        let bytes = b"PUBLIC RECEIPT FIXTURE".to_vec();
        let object = ObjectId::of_ciphertext(&bytes);
        let posted = replica
            .post(
                mailbox.mailbox_id,
                mailbox.write_token,
                object,
                bytes.clone(),
                TransferHint::Eager,
            )
            .await
            .unwrap();
        let receipt = VerifiedReceipt::verify(
            &posted.1,
            replica.key(),
            mailbox.mailbox_id,
            object,
            bytes.len(),
        )
        .unwrap();
        let generation = receipt.body().storage_generation.clone();
        let peer = replica.peer_id();
        let mailbox = mailbox.mailbox_id;
        let dir = tempfile::tempdir().unwrap();
        let store = ClientStore::open(dir.path()).await.unwrap();
        store
            .stage_inbox(
                peer,
                mailbox,
                generation.clone(),
                InventoryEntry {
                    arrival_seq: 1,
                    object_id: object,
                    size_bytes: bytes.len() as u64,
                    transfer_hint: TransferHint::Eager,
                },
                Some(bytes),
                time(1),
            )
            .await
            .unwrap();
        let changed = "ff".repeat(32);
        let cursor = store
            .begin_scan(peer, mailbox, None, changed.clone(), 0)
            .await
            .unwrap();
        store
            .finish_scan_page(
                peer,
                mailbox,
                cursor,
                Inventory {
                    storage_generation: changed,
                    head: 0,
                    entries: vec![],
                    requested_messages: vec![],
                },
            )
            .await
            .unwrap();
        let target = DeliveryTarget {
            peer_id: peer,
            mailbox_id: mailbox,
        };
        let attempt = store
            .claim_repair(target, time(100), 0)
            .await
            .unwrap()
            .unwrap();
        assert!(
            store
                .confirm_repair(attempt, receipt.clone())
                .await
                .is_err()
        );
        assert_eq!(store.missing_copies().await.unwrap(), 1);
        store
            .reset_peer_cursor(peer, mailbox, generation)
            .await
            .unwrap();
        let stale = store
            .claim_repair(target, time(100_000), 0)
            .await
            .unwrap()
            .unwrap();
        let current = store
            .claim_repair(target, time(200_000), 0)
            .await
            .unwrap()
            .unwrap();
        assert!(store.confirm_repair(stale, receipt.clone()).await.is_err());
        let raw = Connection::open(dir.path().join("client.sqlite")).unwrap();
        raw.execute_batch("CREATE TRIGGER fail_receipt BEFORE UPDATE ON replica_copies BEGIN SELECT RAISE(ABORT,'injected'); END").unwrap();
        // Move-only attempt would normally be retried after backoff following a
        // database error; construct the same internal callback to test rollback.
        let same = RepairAttempt {
            target: current.target,
            object: current.object,
            size: current.size,
            hint: current.hint,
            generation: current.generation.clone(),
            number: current.number,
        };
        assert!(
            store
                .confirm_repair(current, receipt.clone())
                .await
                .is_err()
        );
        assert_eq!(store.missing_copies().await.unwrap(), 1);
        raw.execute_batch("DROP TRIGGER fail_receipt").unwrap();
        store.confirm_repair(same, receipt).await.unwrap();
        assert_eq!(store.missing_copies().await.unwrap(), 0);
        store.close().await.unwrap();
    }
}
