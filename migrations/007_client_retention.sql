BEGIN IMMEDIATE;
ALTER TABLE replica_copies ADD COLUMN pruned_record BLOB;
PRAGMA user_version=7;
COMMIT;
