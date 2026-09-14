-- Durable notification handoff, committed with a verified storage receipt.
-- Only existing record/object identifiers; never device tokens or plaintext.
BEGIN IMMEDIATE;
CREATE TABLE notification_outbox (
    record_id TEXT PRIMARY KEY REFERENCES records(record_id) ON DELETE RESTRICT,
    object_id TEXT NOT NULL REFERENCES objects(object_id) ON DELETE RESTRICT,
    created_local_ms INTEGER NOT NULL CHECK(created_local_ms>=0),
    next_local_ms INTEGER NOT NULL CHECK(next_local_ms>=0),
    completed INTEGER NOT NULL DEFAULT 0 CHECK(completed IN (0,1))
) STRICT;
CREATE INDEX notifications_due ON notification_outbox(completed,next_local_ms);
PRAGMA user_version=6;
COMMIT;
