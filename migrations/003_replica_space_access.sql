-- Hosted Space membership is additional to mailbox read/write capabilities.
BEGIN IMMEDIATE;
CREATE TABLE space_access_roots (
 mailbox_id TEXT PRIMARY KEY NOT NULL REFERENCES mailboxes(mailbox_id) ON DELETE CASCADE
) STRICT;
CREATE TABLE space_access_members (
 mailbox_id TEXT NOT NULL REFERENCES space_access_roots(mailbox_id) ON DELETE CASCADE,
 identity_id TEXT NOT NULL,
 PRIMARY KEY(mailbox_id,identity_id)
) STRICT;
PRAGMA user_version=3;
COMMIT;
