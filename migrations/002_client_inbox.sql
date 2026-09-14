-- Durable transfer work before private record validation; never stores plaintext.
BEGIN IMMEDIATE;
CREATE TABLE inbox (
    peer_id TEXT NOT NULL,
    mailbox_id TEXT NOT NULL,
    storage_generation TEXT NOT NULL,
    arrival_seq INTEGER NOT NULL CHECK(arrival_seq BETWEEN 1 AND 9007199254740991),
    object_id TEXT NOT NULL CHECK(length(object_id)=64 AND object_id NOT GLOB '*[^0-9a-f]*'),
    transfer_hint TEXT NOT NULL CHECK(transfer_hint IN ('eager','lazy')),
    state TEXT NOT NULL CHECK(state IN ('PENDING','ACCEPTED','REJECTED','DEFERRED','WAITING_FOR_PROOF','QUARANTINED_STALE')),
    PRIMARY KEY(peer_id,mailbox_id,storage_generation,arrival_seq)
) STRICT;
CREATE INDEX inbox_pending ON inbox(state,peer_id,mailbox_id,arrival_seq);
PRAGMA user_version=2;
COMMIT;
