//! Bounded presentation queries. Cursors are record IDs scoped to one chat;
//! ordering uses immutable local arrival metadata, never an OFFSET.
use super::*;
use crate::ids::{SpaceId, StreamId};

impl ClientStore {
    pub(crate) async fn message_sources_by_ids(
        &self,
        space: SpaceId,
        stream: StreamId,
        ids: Vec<RecordId>,
    ) -> Result<Vec<DisplaySource>> {
        if ids.len() > 1000 {
            return Err(StoreError::InvalidInput("invalid history refresh size"));
        }
        self.call(move |c| {
            let ids=ids.into_iter().map(|id|id.to_string()).collect::<Vec<_>>();
            let mut q=c.prepare("SELECT record_id FROM records WHERE space_id=?1 AND stream_id=?2 AND kind IN ('chat.message','chat.locator','file.shared') AND status IN ('LOCAL','ACCEPTED') AND record_id IN (SELECT value FROM json_each(?3))")?;
            let selected=q.query_map(params![space.to_string(),stream.to_string(),serde_json::to_string(&ids).expect("string array")],|r|r.get::<_,String>(0))?.collect::<std::result::Result<Vec<_>,_>>()?;
            if selected.len()!=ids.len() {return Err(StoreError::InvalidInput("history records are unavailable in this chat"));}
            sources_for_ids(c,&selected)
        }).await
    }
    pub(crate) async fn message_sources_page(
        &self,
        space: SpaceId,
        stream: StreamId,
        before: Option<RecordId>,
        limit: usize,
        forward: bool,
    ) -> Result<(Vec<DisplaySource>, Option<RecordId>)> {
        if !(1..=1000).contains(&limit) {
            return Err(StoreError::InvalidInput("invalid history page size"));
        }
        self.call(move |c| {
            let boundary = before.map(|id| c.query_row(
                "SELECT first_seen_local_ms FROM records WHERE space_id=?1 AND stream_id=?2 AND record_id=?3 AND kind IN ('chat.message','chat.locator','file.shared') AND status IN ('LOCAL','ACCEPTED')",
                params![space.to_string(), stream.to_string(), id.to_string()], |r|r.get::<_,i64>(0)
            )).transpose()?;
            let comparison=if forward { ">" } else { "<" };
            let direction=if forward { "ASC" } else { "DESC" };
            let mut q = c.prepare(&format!("SELECT record_id FROM records r WHERE space_id=?1 AND stream_id=?2 AND kind IN ('chat.message','chat.locator','file.shared') AND status IN ('LOCAL','ACCEPTED') AND (kind!='chat.locator' OR NOT EXISTS(SELECT 1 FROM message_locators l JOIN records m ON m.record_id=l.message_record_id AND m.status IN ('LOCAL','ACCEPTED') WHERE l.locator_record_id=r.record_id)) AND (?3 IS NULL OR (first_seen_local_ms,record_id){comparison}(?3,?4)) ORDER BY first_seen_local_ms {direction},record_id {direction} LIMIT ?5"))?;
            let mut ids = q.query_map(params![space.to_string(),stream.to_string(),boundary,before.map(|id|id.to_string()),(limit+1) as u32], |r|r.get::<_,String>(0))?.collect::<std::result::Result<Vec<_>,_>>()?;
            let more = ids.len()>limit;
            ids.truncate(limit);
            let cursor = if more { ids.last().map(|id|id.parse()).transpose()? } else {None};
            Ok((sources_for_ids(c, &ids)?, cursor))
        }).await
    }

    pub(crate) async fn summary_sources(
        &self,
        space: SpaceId,
        stream: StreamId,
        seen: Vec<String>,
        unread: Vec<String>,
    ) -> Result<Vec<DisplaySource>> {
        self.call(move |c| {
            // Match the existing activity window. Read/local history is not
            // decrypted merely to draw a chat card. Own copies received from
            // another device are filtered after signature verification.
            let mut q=c.prepare("WITH recent AS (SELECT r.record_id,r.status FROM records r WHERE space_id=?1 AND stream_id=?2 AND kind IN ('chat.message','chat.locator','file.shared') AND status IN ('LOCAL','ACCEPTED') AND (kind!='chat.locator' OR NOT EXISTS(SELECT 1 FROM message_locators l JOIN records m ON m.record_id=l.message_record_id AND m.status IN ('LOCAL','ACCEPTED') WHERE l.locator_record_id=r.record_id)) ORDER BY first_seen_local_ms DESC,record_id DESC LIMIT 1000) SELECT record_id FROM recent WHERE record_id=(SELECT record_id FROM recent LIMIT 1) OR (status!='LOCAL' AND record_id NOT IN (SELECT value FROM json_each(?3))) UNION SELECT record_id FROM records WHERE space_id=?1 AND stream_id=?2 AND kind IN ('chat.message','chat.locator','file.shared') AND status IN ('LOCAL','ACCEPTED') AND record_id IN (SELECT value FROM json_each(?4))")?;
            let ids=q.query_map(params![space.to_string(),stream.to_string(),serde_json::to_string(&seen).expect("string array"),serde_json::to_string(&unread).expect("string array")], |r|r.get::<_,String>(0))?.collect::<std::result::Result<Vec<_>,_>>()?;
            sources_for_ids(c,&ids)
        }).await
    }
}

fn sources_for_ids(c: &Connection, ids: &[String]) -> Result<Vec<DisplaySource>> {
    let mut q=c.prepare("SELECT r.record_id,s.object_id,s.source_index, CASE
      WHEN EXISTS(SELECT 1 FROM outbox o WHERE o.record_id=r.record_id AND o.state='REJECTED' AND COALESCE(o.last_error_code,'')!='REMOTE_PRUNED') THEN 'REJECTED'
      WHEN EXISTS(SELECT 1 FROM outbox o WHERE o.record_id=r.record_id AND o.state='HELD_STALE_CONFIG') THEN 'HELD_STALE_CONFIG'
      WHEN EXISTS(SELECT 1 FROM replica_copies c JOIN outbox o USING(peer_id,mailbox_id,object_id) WHERE o.record_id=r.record_id AND c.missing=1 AND c.pruned_record IS NULL) THEN 'REPAIR_PENDING'
      WHEN EXISTS(SELECT 1 FROM outbox o WHERE o.record_id=r.record_id AND o.state IN ('PENDING','INFLIGHT')) THEN 'QUEUED'
      WHEN EXISTS(SELECT 1 FROM outbox o WHERE o.record_id=r.record_id) AND NOT EXISTS(SELECT 1 FROM outbox o WHERE o.record_id=r.record_id AND o.state!='STORED') THEN 'STORED'
      ELSE r.status END FROM records r JOIN record_sources s USING(record_id) WHERE r.record_id IN (SELECT value FROM json_each(?1)) ORDER BY r.first_seen_local_ms DESC,r.record_id DESC,s.source_index")?;
    let mut rows = q.query([serde_json::to_string(ids).expect("string array")])?;
    let mut result = Vec::new();
    while let Some(r) = rows.next()? {
        result.push(DisplaySource {
            record: r.get::<_, String>(0)?.parse()?,
            object: r.get::<_, String>(1)?.parse()?,
            index: r.get(2)?,
            status: r.get(3)?,
        });
    }
    Ok(result)
}
