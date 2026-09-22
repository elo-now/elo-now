-- Bounded, capability-separated child mailboxes. No invitation semantics or workers.
BEGIN IMMEDIATE;
CREATE TABLE mailbox_delegations (
    mailbox_id TEXT PRIMARY KEY NOT NULL REFERENCES mailboxes(mailbox_id) ON DELETE RESTRICT,
    parent_id TEXT NOT NULL REFERENCES mailboxes(mailbox_id) ON DELETE RESTRICT,
    expires_at INTEGER NOT NULL CHECK(expires_at BETWEEN 1 AND 9007199254740991),
    CHECK(mailbox_id != parent_id)
) STRICT;
CREATE INDEX mailbox_children ON mailbox_delegations(parent_id);
PRAGMA user_version=2;
COMMIT;
