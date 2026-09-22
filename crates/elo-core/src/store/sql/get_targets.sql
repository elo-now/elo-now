SELECT peer_id, mailbox_id FROM outbox WHERE object_id = ?1 ORDER BY peer_id, mailbox_id;
