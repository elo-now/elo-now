//! Removes attributable service-side caches; signed authority proofs remain.
use super::*;
use crate::ids::IdentityId;
impl ClientStore {
    pub async fn erase_account_content(&self, identity: IdentityId) -> Result<()> {
        self.call(move |db| {
            let ids = {
                let mut q = db.prepare("SELECT object_id,ciphertext FROM objects")?;
                let mut rows = q.query([])?;
                let mut ids = Vec::new();
                while let Some(row) = rows.next()? {
                    let bytes: Vec<u8> = row.get(1)?;
                    if crate::erasure::inspect(&bytes).map_err(|_|StoreError::ObjectIntegrity)?.is_some_and(|content|content.subjects.contains(&identity)) { ids.push(row.get::<_,String>(0)?); }
                }
                ids
            };
            db.pragma_update(None,"secure_delete","ON")?;
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            for id in ids {
                for table in ["notification_outbox","outbox","record_sources","inbox","replica_copies"] {
                    tx.execute(&format!("DELETE FROM {table} WHERE object_id=?1"), [&id])?;
                }
                tx.execute("DELETE FROM objects WHERE object_id=?1",[&id])?;
            }
            tx.execute("DELETE FROM message_audit WHERE record_id IN (SELECT record_id FROM records WHERE kind IN ('chat.message','chat.action','history.grant','file.body','file.shared') AND NOT EXISTS(SELECT 1 FROM record_sources s WHERE s.record_id=records.record_id))",[])?;
            tx.execute("DELETE FROM records WHERE kind IN ('chat.message','chat.action','history.grant','file.body','file.shared') AND NOT EXISTS(SELECT 1 FROM record_sources s WHERE s.record_id=records.record_id)",[])?;
            tx.commit()?;
            db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
            Ok(())
        }).await
    }
}
