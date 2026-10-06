-- Local history removal is neither an authority event nor a synchronized setting.
BEGIN IMMEDIATE;
CREATE TABLE local_chat_deletions (
 space_id TEXT NOT NULL CHECK(length(space_id)=64 AND space_id NOT GLOB '*[^0-9a-f]*'),
 stream_id TEXT NOT NULL CHECK(length(stream_id)=32 AND stream_id NOT GLOB '*[^0-9a-f]*'),
 cutoff_ms INTEGER NOT NULL CHECK(cutoff_ms>=0),
 generation INTEGER NOT NULL CHECK(generation>0),
 hidden INTEGER NOT NULL CHECK(hidden IN (0,1)),
 PRIMARY KEY(space_id,stream_id)
) STRICT;
CREATE TABLE local_deleted_records (
 record_id TEXT PRIMARY KEY NOT NULL CHECK(length(record_id)=64 AND record_id NOT GLOB '*[^0-9a-f]*')
) STRICT;
CREATE TABLE local_deleted_targets (
 space_id TEXT NOT NULL CHECK(length(space_id)=64 AND space_id NOT GLOB '*[^0-9a-f]*'),
 stream_id TEXT NOT NULL CHECK(length(stream_id)=32 AND stream_id NOT GLOB '*[^0-9a-f]*'),
 record_id TEXT NOT NULL CHECK(length(record_id)=64 AND record_id NOT GLOB '*[^0-9a-f]*'),
 PRIMARY KEY(space_id,stream_id,record_id)
) STRICT;
CREATE TABLE local_deleted_objects (
 object_id TEXT PRIMARY KEY NOT NULL CHECK(length(object_id)=64 AND object_id NOT GLOB '*[^0-9a-f]*')
) STRICT;
PRAGMA user_version=10;
COMMIT;
