-- Local transport diagnostics only: no content, credentials or response bodies.
BEGIN IMMEDIATE;
CREATE TABLE message_audit_meta (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    started_local_ms INTEGER NOT NULL CHECK(started_local_ms>=0)
) STRICT;
INSERT INTO message_audit_meta VALUES(1,unixepoch()*1000);
CREATE TABLE message_audit (
    sequence INTEGER PRIMARY KEY,
    record_id TEXT NOT NULL REFERENCES records(record_id) ON DELETE RESTRICT,
    at_local_ms INTEGER NOT NULL CHECK(at_local_ms>=0),
    kind TEXT NOT NULL CHECK(kind IN
        ('QUEUED','UPLOAD_STARTED','RETRY_SCHEDULED','STORED','HELD','PROCESS_RESTART',
         'RECEIVED','HISTORY_IMPORTED','REPAIR_STARTED','REPAIRED','REPAIR_FAILED')),
    peer_id TEXT,
    mailbox_id TEXT,
    attempt INTEGER CHECK(attempt IS NULL OR attempt>=0),
    error_code TEXT,
    http_status INTEGER CHECK(http_status IS NULL OR http_status BETWEEN 100 AND 599),
    next_retry_local_ms INTEGER CHECK(next_retry_local_ms IS NULL OR next_retry_local_ms>=0),
    CHECK((peer_id IS NULL AND mailbox_id IS NULL) OR
          (length(peer_id)=64 AND peer_id NOT GLOB '*[^0-9a-f]*' AND
           length(mailbox_id)=64 AND mailbox_id NOT GLOB '*[^0-9a-f]*'))
) STRICT;
CREATE INDEX message_audit_by_record ON message_audit(record_id,sequence);
PRAGMA user_version=5;
COMMIT;
