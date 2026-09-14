BEGIN IMMEDIATE;
CREATE TABLE authority_snapshots (
    space_id TEXT NOT NULL,
    stream_id TEXT NOT NULL,
    ciphertext BLOB NOT NULL CHECK(length(ciphertext) BETWEEN 1 AND 16777216),
    PRIMARY KEY(space_id,stream_id),
    FOREIGN KEY(space_id,stream_id) REFERENCES stream_heads(space_id,stream_id)
) STRICT;
CREATE TABLE used_invites (
    invite_id TEXT PRIMARY KEY NOT NULL CHECK(length(invite_id)=64),
    request_id TEXT NOT NULL CHECK(length(request_id)=64),
    config_id TEXT NOT NULL REFERENCES records(record_id)
) STRICT;
PRAGMA user_version=3;
COMMIT;
