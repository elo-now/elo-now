BEGIN IMMEDIATE;
CREATE TABLE message_locators (
 locator_record_id TEXT PRIMARY KEY NOT NULL REFERENCES records(record_id) ON DELETE CASCADE,
 message_record_id TEXT NOT NULL CHECK(length(message_record_id)=64),
 body_object_id TEXT NOT NULL CHECK(length(body_object_id)=64),
 requested_local_ms INTEGER CHECK(requested_local_ms IS NULL OR requested_local_ms>=0),
 UNIQUE(message_record_id,body_object_id)
) STRICT;
CREATE INDEX message_locators_message ON message_locators(message_record_id);
ALTER TABLE replica_copies ADD COLUMN retention_expired INTEGER NOT NULL DEFAULT 0 CHECK(retention_expired IN (0,1));
PRAGMA user_version=8;
COMMIT;
