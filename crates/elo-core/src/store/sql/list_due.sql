SELECT outbox.record_id, outbox.object_id, outbox.peer_id, outbox.mailbox_id,
       outbox.attempts, outbox.next_attempt_local_ms
FROM outbox
JOIN records ON records.record_id=outbox.record_id
WHERE state = 'PENDING' AND next_attempt_local_ms <= ?1
  AND NOT EXISTS (SELECT 1 FROM replica_copies c WHERE c.peer_id=outbox.peer_id AND c.mailbox_id=outbox.mailbox_id AND c.object_id=outbox.object_id AND c.pruned_record IS NOT NULL)
ORDER BY next_attempt_local_ms,
         CASE records.kind WHEN 'chat.locator' THEN 0 ELSE 1 END,
         object_id, peer_id, mailbox_id
LIMIT ?2;
