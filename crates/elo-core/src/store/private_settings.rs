//! Local durable ordering for encrypted account settings; contents stay encrypted.
use super::*;

impl ClientStore {
    pub(crate) async fn private_settings_sources(
        &self,
        after: i64,
    ) -> Result<Vec<(i64, DisplaySource)>> {
        self.call(move |c| {
            let mut q = c.prepare(
                "SELECT i.sequence,r.record_id,s.object_id,s.source_index,r.status
                 FROM private_settings_inbox i JOIN records r USING(record_id)
                 JOIN record_sources s USING(record_id)
                 WHERE i.sequence>?1 AND r.status IN ('LOCAL','ACCEPTED')
                 AND s.source_index=-1 ORDER BY i.sequence LIMIT 64",
            )?;
            let values = q.query_map([after], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, String>(4)?,
                ))
            })?;
            values
                .map(|row| {
                    let (sequence, record, object, index, status) = row?;
                    Ok((
                        sequence,
                        DisplaySource {
                            record: record.parse()?,
                            object: object.parse()?,
                            index,
                            status,
                        },
                    ))
                })
                .collect()
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn late_permission_proof_receives_a_new_processing_sequence() {
        let temp = tempfile::tempdir().unwrap();
        let store = ClientStore::open(temp.path()).await.unwrap();
        store.call(|c| {
            let tx = c.transaction()?;
            for (id, state) in [("a".repeat(64), "WAITING_FOR_PROOF"), ("b".repeat(64), "ACCEPTED")] {
                tx.execute("INSERT INTO records VALUES(?1,'chat.private-settings',NULL,NULL,NULL,?2,1)",
                    params![id,state])?;
            }
            let early: Vec<String> = tx.prepare("SELECT record_id FROM private_settings_inbox ORDER BY sequence")?
                .query_map([], |row| row.get(0))?.collect::<rusqlite::Result<_>>()?;
            assert_eq!(early, vec!["b".repeat(64)]);
            let cursor: i64 = tx.query_row("SELECT max(sequence) FROM private_settings_inbox",[],|r|r.get(0))?;
            tx.execute("UPDATE records SET status='ACCEPTED' WHERE record_id=?1",["a".repeat(64)])?;
            let late: String = tx.query_row("SELECT record_id FROM private_settings_inbox WHERE sequence>?1",[cursor],|r|r.get(0))?;
            assert_eq!(late,"a".repeat(64));
            tx.commit()?;
            Ok(())
        }).await.unwrap();
        store.close().await.unwrap();
    }
}
