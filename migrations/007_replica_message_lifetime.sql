-- Encrypted message bodies expire while encrypted locators remain discoverable.
BEGIN IMMEDIATE;
CREATE TABLE message_bodies (
 root_mailbox_id TEXT NOT NULL REFERENCES mailboxes(mailbox_id) ON DELETE CASCADE,
 object_id TEXT NOT NULL CHECK(length(object_id)=64),
 record_id TEXT NOT NULL CHECK(length(record_id)=64),
 locator_nonce TEXT NOT NULL CHECK(length(locator_nonce)=32),
 originating_issuer TEXT NOT NULL CHECK(length(originating_issuer)=64),
 direct_peer TEXT CHECK(direct_peer IS NULL OR length(direct_peer)=64),
 lifetime_seconds INTEGER NOT NULL CHECK(lifetime_seconds IN (21600,43200,86400)),
 received_local_ms INTEGER NOT NULL CHECK(received_local_ms>=0),
 expires_local_ms INTEGER NOT NULL CHECK(expires_local_ms>=received_local_ms),
 expired_local_ms INTEGER CHECK(expired_local_ms IS NULL OR expired_local_ms>=received_local_ms),
 refill_until_ms INTEGER CHECK(refill_until_ms IS NULL OR refill_until_ms>=received_local_ms),
 PRIMARY KEY(root_mailbox_id,object_id),
 UNIQUE(root_mailbox_id,record_id)
) STRICT;
CREATE INDEX message_bodies_expiry ON message_bodies(expires_local_ms) WHERE expired_local_ms IS NULL;
CREATE TABLE message_locators (
 root_mailbox_id TEXT NOT NULL REFERENCES mailboxes(mailbox_id) ON DELETE CASCADE,
 object_id TEXT NOT NULL CHECK(length(object_id)=64),
 body_object_id TEXT NOT NULL CHECK(length(body_object_id)=64),
 record_id TEXT NOT NULL CHECK(length(record_id)=64),
 locator_nonce TEXT NOT NULL CHECK(length(locator_nonce)=32),
 lifetime_seconds INTEGER NOT NULL CHECK(lifetime_seconds IN (21600,43200,86400)),
 received_local_ms INTEGER NOT NULL CHECK(received_local_ms>=0),
 expires_local_ms INTEGER NOT NULL CHECK(expires_local_ms>=received_local_ms),
 PRIMARY KEY(root_mailbox_id,object_id),
 UNIQUE(root_mailbox_id,body_object_id),
 UNIQUE(root_mailbox_id,record_id)
) STRICT;
CREATE INDEX message_locators_expiry ON message_locators(expires_local_ms);
CREATE TABLE message_requests (
 root_mailbox_id TEXT NOT NULL,
 body_object_id TEXT NOT NULL,
 record_id TEXT NOT NULL CHECK(length(record_id)=64),
 requester_identity TEXT NOT NULL CHECK(length(requester_identity)=64),
 requested_local_ms INTEGER NOT NULL CHECK(requested_local_ms>=0),
 expires_local_ms INTEGER NOT NULL CHECK(expires_local_ms>=requested_local_ms),
 PRIMARY KEY(root_mailbox_id,body_object_id,requester_identity),
 FOREIGN KEY(root_mailbox_id,body_object_id) REFERENCES message_bodies(root_mailbox_id,object_id) ON DELETE CASCADE
) STRICT;
CREATE INDEX message_requests_expiry ON message_requests(expires_local_ms);
CREATE TABLE message_acceptances (
 root_mailbox_id TEXT NOT NULL,
 body_object_id TEXT NOT NULL,
 accepting_identity TEXT NOT NULL CHECK(length(accepting_identity)=64),
 accepted_local_ms INTEGER NOT NULL CHECK(accepted_local_ms>=0),
 expires_local_ms INTEGER NOT NULL CHECK(expires_local_ms>=accepted_local_ms),
 PRIMARY KEY(root_mailbox_id,body_object_id,accepting_identity),
 FOREIGN KEY(root_mailbox_id,body_object_id) REFERENCES message_bodies(root_mailbox_id,object_id) ON DELETE CASCADE
) STRICT;
CREATE INDEX message_acceptances_expiry ON message_acceptances(expires_local_ms);
PRAGMA user_version=7;
COMMIT;
