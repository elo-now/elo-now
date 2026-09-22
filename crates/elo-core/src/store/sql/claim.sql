UPDATE outbox SET state = 'INFLIGHT', attempts = attempts + 1, last_error_code = NULL
WHERE object_id = ?1 AND peer_id = ?2 AND mailbox_id = ?3
  AND state = 'PENDING' AND attempts = ?4;
