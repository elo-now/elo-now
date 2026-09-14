use super::*;

impl ClientStore {
    pub(crate) async fn pending_notifications(
        &self,
        now: LocalTime,
    ) -> Result<Vec<(RecordId, ObjectId, i64)>> {
        self.call(move |c| {
            c.execute("UPDATE notification_outbox SET completed=1 WHERE completed=0 AND created_local_ms<?",[now.as_millis().saturating_sub(86_400_000)])?;
            let mut q=c.prepare("SELECT record_id,object_id,created_local_ms FROM notification_outbox WHERE completed=0 AND next_local_ms<=? ORDER BY next_local_ms,record_id LIMIT 16")?;
            let rows=q.query_map([now.as_millis()],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,i64>(2)?)))?;
            rows.map(|row| {let (r,o,time)=row?;Ok((r.parse()?,o.parse()?,time))}).collect()
        }).await
    }
    pub(crate) async fn notification_attempted(
        &self,
        record: RecordId,
        completed: bool,
        now: LocalTime,
    ) -> Result<()> {
        self.call(move |c| {
            c.execute(
                "UPDATE notification_outbox SET completed=?,next_local_ms=? WHERE record_id=?",
                params![
                    completed,
                    now.as_millis().saturating_add(30_000),
                    record.to_string()
                ],
            )?;
            Ok(())
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::replica::{ReplicaStore, TransferHint, VerifiedReceipt};
    #[tokio::test]
    async fn receipt_handoff_is_atomic_durable_and_does_not_replay_old_messages() {
        let temp = tempfile::tempdir().unwrap();
        let replica = ReplicaStore::open(temp.path().join("replica"))
            .await
            .unwrap();
        let mailbox = replica.create_mailbox(4096).await.unwrap();
        let mut input = super::super::tests::fixture(91, 0);
        input.metadata = RecordMetadata::new(
            "chat.message",
            input.metadata.space_id(),
            input.metadata.stream_id(),
            input.metadata.config_id(),
        )
        .unwrap();
        input.targets = vec![DeliveryTarget {
            peer_id: replica.peer_id(),
            mailbox_id: mailbox.mailbox_id,
        }];
        let path = temp.path().join("client");
        let store = ClientStore::open(&path).await.unwrap();
        store
            .commit_local_record_with_outbox(input.clone())
            .await
            .unwrap();
        let time = super::super::audit::clock().unwrap();
        assert!(store.pending_notifications(time).await.unwrap().is_empty());
        let attempt = store.claim_next(time).await.unwrap().unwrap();
        let (_, signed) = replica
            .post(
                mailbox.mailbox_id,
                mailbox.write_token,
                input.object_id,
                input.ciphertext.clone(),
                TransferHint::Eager,
            )
            .await
            .unwrap();
        let receipt = VerifiedReceipt::verify(
            &signed,
            replica.key(),
            mailbox.mailbox_id,
            input.object_id,
            input.ciphertext.len(),
        )
        .unwrap();
        store.call(|c|{c.execute_batch("CREATE TEMP TRIGGER fail_notification BEFORE INSERT ON notification_outbox BEGIN SELECT RAISE(ABORT,'synthetic failure'); END;")?;Ok(())}).await.unwrap();
        assert!(
            store
                .confirm_stored(attempt, receipt.clone())
                .await
                .is_err()
        );
        assert!(store.pending_notifications(time).await.unwrap().is_empty());
        assert_eq!(
            store.message_audit(input.record_id).await.unwrap()["targets"][0]["state"],
            "INFLIGHT"
        );
        store
            .call(|c| {
                c.execute_batch("DROP TRIGGER fail_notification")?;
                Ok(())
            })
            .await
            .unwrap();
        store.confirm_stored(attempt, receipt).await.unwrap();
        store.close().await.unwrap();
        let store = ClientStore::open(&path).await.unwrap();
        let time = super::super::audit::clock().unwrap();
        let pending = store.pending_notifications(time).await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].0, input.record_id);
        store
            .notification_attempted(input.record_id, false, time)
            .await
            .unwrap();
        assert!(store.pending_notifications(time).await.unwrap().is_empty());
        let later = LocalTime::from_millis(time.as_millis() as u64 + 30_001).unwrap();
        assert_eq!(store.pending_notifications(later).await.unwrap().len(), 1);
        store
            .notification_attempted(input.record_id, true, later)
            .await
            .unwrap();
        store.close().await.unwrap();
        let store = ClientStore::open(&path).await.unwrap();
        assert!(store.pending_notifications(later).await.unwrap().is_empty());
        assert_eq!(
            store.get_object(input.object_id).await.unwrap(),
            Some(input.ciphertext)
        );
        store.close().await.unwrap();
    }
}
