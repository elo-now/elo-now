UPDATE outbox
SET state = 'PENDING', next_attempt_local_ms = ?5, last_error_code = ?6
WHERE object_id = ?1 AND peer_id = ?2 AND mailbox_id = ?3
  AND state = 'INFLIGHT' AND attempts = ?4;
