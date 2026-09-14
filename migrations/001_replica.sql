-- elo.now experimental replica schema v1. Use a SEPARATE database from the client.
-- Ciphertext only. No HUMAN secret, original record projection or authority grant.
BEGIN IMMEDIATE;
CREATE TABLE node_meta (
    key TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL
) STRICT;
-- Application initialization sets a random public storage_generation; on restore,
-- replace it before serving. It is a consistency marker, NOT a secret or proof.
CREATE TABLE mailboxes (
    mailbox_id TEXT PRIMARY KEY NOT NULL CHECK(length(mailbox_id)=64 AND mailbox_id NOT GLOB '*[^0-9a-f]*'),
    read_token_hash BLOB NOT NULL CHECK(length(read_token_hash)=32),
    write_token_hash BLOB NOT NULL CHECK(length(write_token_hash)=32),
    quota_bytes INTEGER NOT NULL CHECK(quota_bytes BETWEEN 1 AND 9007199254740991),
    CHECK(read_token_hash != write_token_hash)
) STRICT;
CREATE TABLE objects (
    object_id TEXT PRIMARY KEY NOT NULL CHECK(length(object_id)=64 AND object_id NOT GLOB '*[^0-9a-f]*'),
    ciphertext BLOB NOT NULL CHECK(length(ciphertext) BETWEEN 1 AND 16777216),
    size_bytes INTEGER NOT NULL CHECK(size_bytes=length(ciphertext)),
    stored_local_ms INTEGER NOT NULL CHECK(stored_local_ms>=0)
) STRICT;
CREATE TRIGGER objects_no_update BEFORE UPDATE ON objects
BEGIN SELECT RAISE(ABORT,'objects are immutable; insert a different object_id'); END;
CREATE TABLE deliveries (
    arrival_seq INTEGER PRIMARY KEY AUTOINCREMENT CHECK(arrival_seq<=9007199254740991),
    mailbox_id TEXT NOT NULL REFERENCES mailboxes(mailbox_id) ON DELETE RESTRICT,
    object_id TEXT NOT NULL REFERENCES objects(object_id) ON DELETE RESTRICT,
    transfer_hint TEXT NOT NULL CHECK(transfer_hint IN ('eager','lazy')),
    UNIQUE(mailbox_id,object_id)
) STRICT;
CREATE INDEX inventory_page ON deliveries(mailbox_id,arrival_seq);
-- No automatic deletion/GC in A/B. Quota must be checked in the same transaction
-- as object+delivery insertion. No silent eviction after a STORED declaration.
PRAGMA user_version=1;
COMMIT;
