-- Inventory observations are transport evidence, never authorization grants.
BEGIN IMMEDIATE;
ALTER TABLE peer_cursors ADD COLUMN local_epoch INTEGER NOT NULL DEFAULT 0 CHECK(local_epoch>=0);
ALTER TABLE inbox RENAME TO inbox_v3;
DROP INDEX inbox_pending;
CREATE TABLE inbox (
    peer_id TEXT NOT NULL,
    mailbox_id TEXT NOT NULL,
    storage_generation TEXT NOT NULL,
    arrival_seq INTEGER NOT NULL CHECK(arrival_seq BETWEEN 1 AND 9007199254740991),
    object_id TEXT NOT NULL CHECK(length(object_id)=64 AND object_id NOT GLOB '*[^0-9a-f]*'),
    transfer_hint TEXT NOT NULL CHECK(transfer_hint IN ('eager','lazy')),
    state TEXT NOT NULL CHECK(state IN ('PENDING','ACCEPTED','REJECTED','DEFERRED','WAITING_FOR_PROOF','QUARANTINED_STALE')),
    local_epoch INTEGER NOT NULL DEFAULT 0 CHECK(local_epoch>=0),
    PRIMARY KEY(peer_id,mailbox_id,storage_generation,local_epoch,arrival_seq)
) STRICT;
INSERT INTO inbox SELECT *,0 FROM inbox_v3;
DROP TABLE inbox_v3;
CREATE INDEX inbox_pending ON inbox(state,peer_id,mailbox_id,arrival_seq);
CREATE TABLE replica_scans (
    peer_id TEXT NOT NULL,
    mailbox_id TEXT NOT NULL,
    storage_generation TEXT NOT NULL,
    round INTEGER NOT NULL CHECK(round>=1),
    after_seq INTEGER NOT NULL CHECK(after_seq>=0),
    head INTEGER NOT NULL CHECK(head>=0),
    complete INTEGER NOT NULL CHECK(complete IN (0,1)),
    PRIMARY KEY(peer_id,mailbox_id)
) STRICT;
CREATE TABLE replica_copies (
    peer_id TEXT NOT NULL,
    mailbox_id TEXT NOT NULL,
    object_id TEXT NOT NULL CHECK(length(object_id)=64 AND object_id NOT GLOB '*[^0-9a-f]*'),
    size_bytes INTEGER NOT NULL CHECK(size_bytes BETWEEN 0 AND 16777216),
    transfer_hint TEXT NOT NULL CHECK(transfer_hint IN ('eager','lazy')),
    seen_round INTEGER NOT NULL DEFAULT 0 CHECK(seen_round>=0),
    missing INTEGER NOT NULL DEFAULT 0 CHECK(missing IN (0,1)),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts>=0),
    next_attempt_local_ms INTEGER NOT NULL DEFAULT 0 CHECK(next_attempt_local_ms>=0),
    receipt_record BLOB,
    PRIMARY KEY(peer_id,mailbox_id,object_id)
) STRICT;
CREATE INDEX replica_repair_due ON replica_copies(peer_id,mailbox_id,missing,next_attempt_local_ms);
-- Old deferred entries have no recorded size; zero means unknown, never empty data.
INSERT INTO replica_copies(peer_id,mailbox_id,object_id,size_bytes,transfer_hint)
SELECT DISTINCT i.peer_id,i.mailbox_id,i.object_id,coalesce(o.size_bytes,0),i.transfer_hint
FROM inbox i LEFT JOIN objects o USING(object_id) WHERE true ON CONFLICT DO NOTHING;
INSERT INTO replica_copies(peer_id,mailbox_id,object_id,size_bytes,transfer_hint,receipt_record)
SELECT b.peer_id,b.mailbox_id,b.object_id,o.size_bytes,
       CASE WHEN r.kind='file.body' THEN 'lazy' ELSE 'eager' END,b.receipt_record
FROM outbox b JOIN objects o USING(object_id) JOIN records r USING(record_id)
WHERE b.state='STORED'
ON CONFLICT(peer_id,mailbox_id,object_id) DO UPDATE SET receipt_record=excluded.receipt_record;
PRAGMA user_version=4;
COMMIT;
