-- A durable local processing order, not a remote read receipt or plaintext index.
BEGIN IMMEDIATE;
CREATE TABLE private_settings_inbox (
 sequence INTEGER PRIMARY KEY AUTOINCREMENT,
 record_id TEXT NOT NULL UNIQUE REFERENCES records(record_id) ON DELETE CASCADE
) STRICT;
CREATE TRIGGER private_settings_received AFTER INSERT ON records
WHEN NEW.kind='chat.private-settings' AND NEW.status IN ('LOCAL','ACCEPTED')
BEGIN
 INSERT OR IGNORE INTO private_settings_inbox(record_id) VALUES(NEW.record_id);
END;
CREATE TRIGGER private_settings_admitted AFTER UPDATE OF status ON records
WHEN NEW.kind='chat.private-settings' AND NEW.status IN ('LOCAL','ACCEPTED')
AND OLD.status NOT IN ('LOCAL','ACCEPTED')
BEGIN
 DELETE FROM private_settings_inbox WHERE record_id=NEW.record_id;
 INSERT INTO private_settings_inbox(record_id) VALUES(NEW.record_id);
END;
PRAGMA user_version=9;
COMMIT;
