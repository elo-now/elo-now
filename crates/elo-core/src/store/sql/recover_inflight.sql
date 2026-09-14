UPDATE outbox
SET state = 'PENDING', next_attempt_local_ms = 0, last_error_code = 'PROCESS_RESTART'
WHERE state = 'INFLIGHT';
