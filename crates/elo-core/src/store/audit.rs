//! A bounded local transport journal, committed with the delivery transition.
//! Never store arbitrary errors, URLs, headers, response bodies or plaintext.
use super::*;
use serde_json::{Value, json};

pub(crate) const AUDIT_LIMIT: usize = 200;

#[derive(Clone, Copy, Debug)]
pub enum TransportFailure {
    Network,
    Timeout,
    Dns,
    Connect,
    Tls,
    TlsRevoked,
    TlsExpired,
    TlsUntrusted,
    Http(u16),
    InvalidResponse,
    InvalidReceipt,
    InvalidReceiptResponse(u16),
}
impl TransportFailure {
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::Network => "NETWORK",
            Self::Timeout => "TIMEOUT",
            Self::Dns => "DNS",
            Self::Connect => "CONNECT",
            Self::Tls => "TLS",
            Self::TlsRevoked => "TLS_REVOKED",
            Self::TlsExpired => "TLS_EXPIRED",
            Self::TlsUntrusted => "TLS_UNTRUSTED",
            Self::Http(_) => "HTTP",
            Self::InvalidResponse => "INVALID_RESPONSE",
            Self::InvalidReceipt | Self::InvalidReceiptResponse(_) => "INVALID_RECEIPT",
        }
    }
    pub(crate) fn http_status(self) -> Option<u16> {
        match self {
            Self::Http(status) | Self::InvalidReceiptResponse(status) => Some(status),
            _ => None,
        }
    }
}

pub(super) struct Event {
    pub kind: &'static str,
    pub target: Option<DeliveryTarget>,
    pub attempt: Option<i64>,
    pub failure: Option<TransportFailure>,
    pub http_status: Option<u16>,
    pub next_retry: Option<LocalTime>,
}
impl Event {
    pub fn new(kind: &'static str, target: Option<DeliveryTarget>) -> Self {
        Self {
            kind,
            target,
            attempt: None,
            failure: None,
            http_status: None,
            next_retry: None,
        }
    }
}

pub(super) fn clock() -> Result<LocalTime> {
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| StoreError::InvalidInput("invalid local clock"))?
        .as_millis();
    LocalTime::from_millis(
        u64::try_from(ms).map_err(|_| StoreError::InvalidInput("invalid local clock"))?,
    )
}

/// The caller owns the transaction, including retention pruning.
pub(super) fn append(c: &Connection, record: RecordId, at: LocalTime, event: &Event) -> Result<()> {
    c.execute("INSERT INTO message_audit(record_id,at_local_ms,kind,peer_id,mailbox_id,attempt,error_code,http_status,next_retry_local_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        params![record.to_string(),at.as_millis(),event.kind,event.target.map(|t|t.peer_id.to_string()),event.target.map(|t|t.mailbox_id.to_string()),event.attempt,event.failure.map(TransportFailure::code),event.http_status.or_else(||event.failure.and_then(TransportFailure::http_status)),event.next_retry.map(|t|t.as_millis())])?;
    c.execute("DELETE FROM message_audit WHERE record_id=?1 AND sequence NOT IN (SELECT sequence FROM message_audit WHERE record_id=?1 ORDER BY sequence DESC LIMIT ?2)",params![record.to_string(),AUDIT_LIMIT as i64])?;
    Ok(())
}

pub(super) fn append_object(
    c: &Connection,
    object: ObjectId,
    at: LocalTime,
    event: &Event,
) -> Result<()> {
    let mut q = c.prepare("SELECT DISTINCT record_id FROM record_sources WHERE object_id=?1")?;
    let records = q
        .query_map([object.to_string()], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for record in records {
        append(c, record.parse()?, at, event)?;
    }
    Ok(())
}

impl ClientStore {
    pub(crate) async fn message_audit(&self, record: RecordId) -> Result<Value> {
        self.call(move |c| {
            let (first_seen,status):(i64,String)=c.query_row("SELECT first_seen_local_ms,status FROM records WHERE record_id=?1",[record.to_string()],|r|Ok((r.get(0)?,r.get(1)?)))?;
            let since:i64=c.query_row("SELECT started_local_ms FROM message_audit_meta WHERE singleton=1",[],|r|r.get(0))?;
            let mut q=c.prepare("SELECT sequence,at_local_ms,kind,peer_id,mailbox_id,attempt,error_code,http_status,next_retry_local_ms FROM message_audit WHERE record_id=?1 ORDER BY sequence")?;
            let events=q.query_map([record.to_string()],|r|Ok(json!({"sequence":r.get::<_,i64>(0)?,"at":r.get::<_,i64>(1)?,"kind":r.get::<_,String>(2)?,"peer":r.get::<_,Option<String>>(3)?,"mailbox":r.get::<_,Option<String>>(4)?,"attempt":r.get::<_,Option<i64>>(5)?,"error":r.get::<_,Option<String>>(6)?,"http_status":r.get::<_,Option<u16>>(7)?,"next_retry":r.get::<_,Option<i64>>(8)?})))?.collect::<rusqlite::Result<Vec<_>>>()?;
            let mut q=c.prepare("SELECT object_id,peer_id,mailbox_id,state,attempts,next_attempt_local_ms,last_error_code,receipt_record FROM outbox WHERE record_id=?1 ORDER BY peer_id,mailbox_id")?;
            let targets=q.query_map([record.to_string()],|r| {
                // Receipts were verified on admission. Expose a strict metadata projection,
                // not signed bytes or arbitrary response fields.
                let receipt=r.get::<_,Option<Vec<u8>>>(7)?.and_then(|bytes|crate::record::SignedRecord::parse(&bytes).ok()).and_then(|r|r.decode::<crate::replica::ReceiptBody>().ok()).map(|b|json!({"stored_at":b.stored_local_ms,"arrival_seq":b.arrival_seq,"size_bytes":b.size_bytes,"generation":b.storage_generation}));
                Ok(json!({"object":r.get::<_,String>(0)?,"peer":r.get::<_,String>(1)?,"mailbox":r.get::<_,String>(2)?,"state":r.get::<_,String>(3)?,"attempts":r.get::<_,i64>(4)?,"next_retry":r.get::<_,i64>(5)?,"last_error":r.get::<_,Option<String>>(6)?,"receipt":receipt}))
            })?.collect::<rusqlite::Result<Vec<_>>>()?;
            let mut q=c.prepare("SELECT DISTINCT s.object_id,s.source_index,i.peer_id,i.mailbox_id,i.state,i.arrival_seq FROM record_sources s LEFT JOIN inbox i USING(object_id) WHERE s.record_id=?1 ORDER BY s.object_id,s.source_index,i.peer_id,i.mailbox_id LIMIT 200")?;
            let sources=q.query_map([record.to_string()],|r|Ok(json!({"object":r.get::<_,String>(0)?,"history":r.get::<_,i64>(1)?>=0,"peer":r.get::<_,Option<String>>(2)?,"mailbox":r.get::<_,Option<String>>(3)?,"state":r.get::<_,Option<String>>(4)?,"arrival_seq":r.get::<_,Option<i64>>(5)?})))?.collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(json!({"first_seen":first_seen,"local_state":status,"journal_since":since,"event_limit":AUDIT_LIMIT,"events":events,"targets":targets,"sources":sources}))
        }).await
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{fixture, time};
    use super::*;

    #[tokio::test]
    async fn upgrade_preserves_old_history_and_does_not_invent_events() {
        let dir = tempfile::tempdir().unwrap();
        let input = fixture(76, 1);
        let store = ClientStore::open(dir.path()).await.unwrap();
        store
            .commit_local_record_with_outbox(input.clone())
            .await
            .unwrap();
        store.close().await.unwrap();
        let old = Connection::open(dir.path().join("client.sqlite")).unwrap();
        old.execute_batch("DROP TABLE notification_outbox; DROP TABLE message_audit; DROP TABLE message_audit_meta; PRAGMA user_version=4; UPDATE outbox SET attempts=7,last_error_code='REMOTE_UNAVAILABLE'").unwrap();
        drop(old);
        let store = ClientStore::open(dir.path()).await.unwrap();
        assert_eq!(
            store.get_object(input.object_id).await.unwrap().unwrap(),
            input.ciphertext
        );
        let audit = store.message_audit(input.record_id).await.unwrap();
        assert_eq!(audit["first_seen"], 100);
        assert_eq!(audit["events"], json!([]));
        assert_eq!(audit["targets"][0]["attempts"], 7);
        assert_eq!(audit["targets"][0]["last_error"], "REMOTE_UNAVAILABLE");
        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn journal_failure_rolls_back_claim_and_stale_results_cannot_append() {
        let dir = tempfile::tempdir().unwrap();
        let input = fixture(77, 1);
        let store = ClientStore::open(dir.path()).await.unwrap();
        store
            .commit_local_record_with_outbox(input.clone())
            .await
            .unwrap();
        store.call(|c| { c.execute_batch("CREATE TEMP TRIGGER fail_audit BEFORE INSERT ON message_audit BEGIN SELECT RAISE(ABORT,'audit failure'); END;")?; Ok(()) }).await.unwrap();
        assert!(store.claim_next(time(100)).await.is_err());
        assert_eq!(
            store.message_audit(input.record_id).await.unwrap()["targets"][0]["attempts"],
            0
        );
        store
            .call(|c| {
                c.execute_batch("DROP TRIGGER fail_audit")?;
                Ok(())
            })
            .await
            .unwrap();
        let attempt = store.claim_next(time(100)).await.unwrap().unwrap();
        store
            .retry_with_diagnostics(
                attempt,
                time(200),
                RetryReason::RemoteUnavailable,
                Some(TransportFailure::Http(503)),
            )
            .await
            .unwrap();
        let before = store.message_audit(input.record_id).await.unwrap();
        assert_eq!(before["events"][2]["http_status"], 503);
        assert!(
            store
                .retry_with_diagnostics(
                    attempt,
                    time(300),
                    RetryReason::RemoteUnavailable,
                    Some(TransportFailure::Http(401))
                )
                .await
                .is_err()
        );
        assert_eq!(store.message_audit(input.record_id).await.unwrap(), before);
        store.close().await.unwrap();
        let store = ClientStore::open(dir.path()).await.unwrap();
        assert_eq!(store.message_audit(input.record_id).await.unwrap(), before);
        store.close().await.unwrap();
    }

    #[tokio::test]
    async fn retention_and_interrupted_attempt_recovery_preserve_totals() {
        let dir = tempfile::tempdir().unwrap();
        let input = fixture(78, 1);
        let store = ClientStore::open(dir.path()).await.unwrap();
        store
            .commit_local_record_with_outbox(input.clone())
            .await
            .unwrap();
        for i in 0..110 {
            let attempt = store.claim_next(time(100 + i)).await.unwrap().unwrap();
            store
                .retry_with_diagnostics(
                    attempt,
                    time(101 + i),
                    RetryReason::RemoteUnavailable,
                    Some(TransportFailure::TlsRevoked),
                )
                .await
                .unwrap();
        }
        store.claim_next(time(300)).await.unwrap().unwrap();
        store.close().await.unwrap();
        let store = ClientStore::open(dir.path()).await.unwrap();
        let audit = store.message_audit(input.record_id).await.unwrap();
        assert_eq!(audit["events"].as_array().unwrap().len(), AUDIT_LIMIT);
        assert_eq!(
            audit["events"].as_array().unwrap().last().unwrap()["kind"],
            "PROCESS_RESTART"
        );
        assert_eq!(audit["targets"][0]["attempts"], 111);
        assert_eq!(audit["targets"][0]["state"], "PENDING");
        store.close().await.unwrap();
    }
}
