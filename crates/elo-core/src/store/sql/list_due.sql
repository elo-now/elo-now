SELECT record_id, object_id, peer_id, mailbox_id, attempts, next_attempt_local_ms
FROM outbox
WHERE state = 'PENDING' AND next_attempt_local_ms <= ?1
ORDER BY next_attempt_local_ms, object_id, peer_id, mailbox_id
LIMIT ?2;
