-- Lossless physical interning; wire objects, hashes, receipts and quotas stay unchanged.
BEGIN IMMEDIATE;
CREATE TABLE object_credentials (
 credential_id BLOB PRIMARY KEY NOT NULL CHECK(length(credential_id)=32),
 encoded BLOB NOT NULL CHECK(length(encoded) BETWEEN 1 AND 131072)
) STRICT, WITHOUT ROWID;
CREATE TRIGGER object_credentials_no_update BEFORE UPDATE ON object_credentials
BEGIN SELECT RAISE(ABORT,'credentials are immutable'); END;
ALTER TABLE objects ADD COLUMN credential_id BLOB REFERENCES object_credentials(credential_id) ON DELETE RESTRICT;
ALTER TABLE objects ADD COLUMN credential_offset INTEGER;
ALTER TABLE objects ADD COLUMN wire_size_bytes INTEGER CHECK(
 (credential_id IS NULL AND credential_offset IS NULL AND wire_size_bytes IS NULL)
 OR (credential_id IS NOT NULL AND credential_offset IS NOT NULL AND wire_size_bytes IS NOT NULL
 AND credential_offset BETWEEN 0 AND size_bytes AND wire_size_bytes BETWEEN size_bytes+1 AND 16777216)
);
CREATE INDEX objects_credential ON objects(credential_id) WHERE credential_id IS NOT NULL;
CREATE TRIGGER objects_packing_size BEFORE INSERT ON objects WHEN NEW.credential_id IS NOT NULL
BEGIN SELECT CASE WHEN NEW.wire_size_bytes != NEW.size_bytes + (SELECT length(encoded) FROM object_credentials WHERE credential_id=NEW.credential_id)
 THEN RAISE(ABORT,'invalid packed object size') END; END;
CREATE TRIGGER objects_credential_cleanup AFTER DELETE ON objects WHEN OLD.credential_id IS NOT NULL
BEGIN DELETE FROM object_credentials WHERE credential_id=OLD.credential_id
 AND NOT EXISTS(SELECT 1 FROM objects WHERE credential_id=OLD.credential_id); END;
PRAGMA user_version=6;
COMMIT;
