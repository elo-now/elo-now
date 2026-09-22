-- Authenticated outer content ownership; plaintext never enters the replica.
BEGIN IMMEDIATE;
CREATE TABLE object_owners (
 object_id TEXT NOT NULL REFERENCES objects(object_id) ON DELETE CASCADE,
 identity_id TEXT NOT NULL CHECK(length(identity_id)=64),
 PRIMARY KEY(object_id,identity_id)
) STRICT;
CREATE INDEX object_owners_identity ON object_owners(identity_id);
CREATE TABLE erased_identities (
 identity_id TEXT PRIMARY KEY NOT NULL CHECK(length(identity_id)=64),
 erased_local_ms INTEGER NOT NULL
) STRICT;
-- Old opaque objects cannot safely be attributed retroactively.
INSERT INTO node_meta(key,value) VALUES('erasure_coverage',CASE WHEN EXISTS(SELECT 1 FROM objects) THEN 'legacy' ELSE 'complete' END);
PRAGMA user_version=5;
COMMIT;
