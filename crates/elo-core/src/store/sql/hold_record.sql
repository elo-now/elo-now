UPDATE outbox SET state = 'HELD_STALE_CONFIG', last_error_code = 'STALE_CONFIG'
WHERE record_id = ?1 AND state IN ('PENDING', 'INFLIGHT');
