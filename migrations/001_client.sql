-- elo.now experimental client schema v1. Apply once to a new CLIENT database.
-- Connection PRAGMAs are set by the caller, not inside this transaction.
-- IDs are lower-case hex. This schema does NOT verify signatures or authorization.
BEGIN IMMEDIATE;
CREATE TABLE objects (
    object_id TEXT PRIMARY KEY NOT NULL
        CHECK(length(object_id)=64 AND object_id NOT GLOB '*[^0-9a-f]*'),
    ciphertext BLOB NOT NULL CHECK(length(ciphertext) BETWEEN 1 AND 16777216),
    size_bytes INTEGER NOT NULL CHECK(size_bytes=length(ciphertext)),
    stored_local_ms INTEGER NOT NULL CHECK(stored_local_ms>=0)
) STRICT;
CREATE TRIGGER objects_no_update BEFORE UPDATE ON objects
BEGIN SELECT RAISE(ABORT,'objects are immutable; insert a different object_id'); END;

CREATE TABLE records (
    record_id TEXT PRIMARY KEY NOT NULL
        CHECK(length(record_id)=64 AND record_id NOT GLOB '*[^0-9a-f]*'),
    kind TEXT NOT NULL CHECK(length(kind) BETWEEN 1 AND 64),
    space_id TEXT CHECK(space_id IS NULL OR (length(space_id)=64 AND space_id NOT GLOB '*[^0-9a-f]*')),
    stream_id TEXT CHECK(stream_id IS NULL OR (length(stream_id)=32 AND stream_id NOT GLOB '*[^0-9a-f]*')),
    config_id TEXT CHECK(config_id IS NULL OR (length(config_id)=64 AND config_id NOT GLOB '*[^0-9a-f]*')),
    status TEXT NOT NULL CHECK(status IN
        ('LOCAL','ACCEPTED','WAITING_FOR_PROOF','QUARANTINED_STALE','REJECTED')),
    first_seen_local_ms INTEGER NOT NULL CHECK(first_seen_local_ms>=0)
) STRICT;
CREATE INDEX records_by_stream ON records(space_id,stream_id,first_seen_local_ms,record_id);

-- Multiple encrypted sources preserve disclosure provenance without duplicate messages.
CREATE TABLE record_sources (
    record_id TEXT NOT NULL REFERENCES records(record_id) ON DELETE RESTRICT,
    object_id TEXT NOT NULL REFERENCES objects(object_id) ON DELETE RESTRICT,
    source_index INTEGER NOT NULL CHECK(source_index BETWEEN -1 AND 99),
    PRIMARY KEY(record_id,object_id,source_index),
    UNIQUE(object_id,source_index)
) STRICT;

CREATE TABLE outbox (
    record_id TEXT NOT NULL REFERENCES records(record_id) ON DELETE RESTRICT,
    object_id TEXT NOT NULL REFERENCES objects(object_id) ON DELETE RESTRICT,
    peer_id TEXT NOT NULL CHECK(length(peer_id)=64 AND peer_id NOT GLOB '*[^0-9a-f]*'),
    mailbox_id TEXT NOT NULL CHECK(length(mailbox_id)=64 AND mailbox_id NOT GLOB '*[^0-9a-f]*'),
    state TEXT NOT NULL DEFAULT 'PENDING'
        CHECK(state IN ('PENDING','INFLIGHT','STORED','HELD_STALE_CONFIG','REJECTED')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts>=0),
    next_attempt_local_ms INTEGER NOT NULL DEFAULT 0 CHECK(next_attempt_local_ms>=0),
    last_error_code TEXT,
    receipt_record BLOB,
    CHECK(state!='STORED' OR receipt_record IS NOT NULL),
    PRIMARY KEY(object_id,peer_id,mailbox_id)
) STRICT;
CREATE INDEX outbox_due ON outbox(state,next_attempt_local_ms);

-- These are local caches, NOT independently trusted snapshots.
CREATE TABLE stream_heads (
    space_id TEXT NOT NULL CHECK(length(space_id)=64 AND space_id NOT GLOB '*[^0-9a-f]*'),
    stream_id TEXT NOT NULL CHECK(length(stream_id)=32 AND stream_id NOT GLOB '*[^0-9a-f]*'),
    config_id TEXT NOT NULL REFERENCES records(record_id) ON DELETE RESTRICT,
    config_sequence INTEGER NOT NULL CHECK(config_sequence BETWEEN 1 AND 9007199254740991),
    state TEXT NOT NULL DEFAULT 'KNOWN' CHECK(state IN ('KNOWN','FORKED')),
    PRIMARY KEY(space_id,stream_id)
) STRICT;
CREATE TABLE peer_cursors (
    peer_id TEXT NOT NULL CHECK(length(peer_id)=64 AND peer_id NOT GLOB '*[^0-9a-f]*'),
    mailbox_id TEXT NOT NULL CHECK(length(mailbox_id)=64 AND mailbox_id NOT GLOB '*[^0-9a-f]*'),
    storage_generation TEXT NOT NULL CHECK(length(storage_generation)=64 AND storage_generation NOT GLOB '*[^0-9a-f]*'),
    arrival_seq INTEGER NOT NULL CHECK(arrival_seq BETWEEN 0 AND 9007199254740991),
    PRIMARY KEY(peer_id,mailbox_id)
) STRICT;
PRAGMA user_version=1;
COMMIT;
