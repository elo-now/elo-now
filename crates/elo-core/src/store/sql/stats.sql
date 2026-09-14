SELECT
    (SELECT count(*) FROM objects),
    (SELECT count(*) FROM records),
    (SELECT count(*) FROM record_sources),
    (SELECT count(*) FROM outbox WHERE state = 'PENDING'),
    (SELECT count(*) FROM outbox WHERE state = 'INFLIGHT'),
    (SELECT count(*) FROM outbox WHERE state = 'STORED'),
    (SELECT count(*) FROM outbox WHERE state = 'HELD_STALE_CONFIG'),
    (SELECT count(*) FROM outbox WHERE state = 'REJECTED');
