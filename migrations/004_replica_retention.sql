-- Message classification is a client retention hint, not an authorization proof.
-- Unclassified records (including records uploaded by older clients) are retained.
BEGIN IMMEDIATE;
CREATE TABLE message_copies (
    mailbox_id TEXT NOT NULL,
    object_id TEXT NOT NULL,
    stored_local_ms INTEGER NOT NULL CHECK(stored_local_ms>=0),
    PRIMARY KEY(mailbox_id,object_id),
    FOREIGN KEY(mailbox_id,object_id) REFERENCES deliveries(mailbox_id,object_id) ON DELETE CASCADE
) STRICT;
CREATE INDEX message_copies_age ON message_copies(stored_local_ms);
CREATE TABLE pruned_objects (
    root_mailbox_id TEXT NOT NULL REFERENCES mailboxes(mailbox_id) ON DELETE CASCADE,
    object_id TEXT NOT NULL CHECK(length(object_id)=64 AND object_id NOT GLOB '*[^0-9a-f]*'),
    pruned_local_ms INTEGER NOT NULL CHECK(pruned_local_ms>=0),
    PRIMARY KEY(root_mailbox_id,object_id)
) STRICT;
PRAGMA user_version=4;
COMMIT;
