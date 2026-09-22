INSERT INTO outbox(record_id, object_id, peer_id, mailbox_id, next_attempt_local_ms)
VALUES (?1, ?2, ?3, ?4, ?5);
