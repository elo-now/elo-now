-- Explicit policies replace numeric-only lifetimes. Existing deadlines are
-- copied verbatim; opening an older database must never restart a lifetime.
PRAGMA foreign_keys=OFF;
BEGIN IMMEDIATE;
CREATE TABLE message_bodies_v10 (
 root_mailbox_id TEXT NOT NULL REFERENCES mailboxes(mailbox_id) ON DELETE CASCADE,
 object_id TEXT NOT NULL CHECK(length(object_id)=64),
 record_id TEXT NOT NULL CHECK(length(record_id)=64),
 locator_nonce TEXT NOT NULL CHECK(length(locator_nonce)=32),
 originating_issuer TEXT NOT NULL CHECK(length(originating_issuer)=64),
 direct_peer TEXT CHECK(direct_peer IS NULL OR length(direct_peer)=64),
 retention_policy TEXT NOT NULL CHECK(retention_policy IN ('6h','12h','24h','48h','no_expiry')),
 received_local_ms INTEGER NOT NULL CHECK(received_local_ms>=0),
 expires_local_ms INTEGER CHECK(expires_local_ms IS NULL OR expires_local_ms>=received_local_ms),
 expired_local_ms INTEGER CHECK(expired_local_ms IS NULL OR expired_local_ms>=received_local_ms),
 refill_until_ms INTEGER CHECK(refill_until_ms IS NULL OR refill_until_ms>=received_local_ms),
 request_key TEXT,
 accept_key TEXT,
 CHECK((retention_policy='no_expiry' AND expires_local_ms IS NULL) OR (retention_policy!='no_expiry' AND expires_local_ms IS NOT NULL)),
 PRIMARY KEY(root_mailbox_id,object_id),
 UNIQUE(root_mailbox_id,record_id)
) STRICT;
INSERT INTO message_bodies_v10 SELECT root_mailbox_id,object_id,record_id,locator_nonce,originating_issuer,direct_peer,
 CASE lifetime_seconds WHEN 21600 THEN '6h' WHEN 43200 THEN '12h' WHEN 86400 THEN '24h' END,
 received_local_ms,expires_local_ms,expired_local_ms,refill_until_ms,request_key,accept_key FROM message_bodies;
DROP TABLE message_bodies;
ALTER TABLE message_bodies_v10 RENAME TO message_bodies;
CREATE INDEX message_bodies_expiry ON message_bodies(expires_local_ms) WHERE expired_local_ms IS NULL;
CREATE TABLE message_locators_v10 (
 root_mailbox_id TEXT NOT NULL REFERENCES mailboxes(mailbox_id) ON DELETE CASCADE,
 object_id TEXT NOT NULL CHECK(length(object_id)=64),
 body_object_id TEXT NOT NULL CHECK(length(body_object_id)=64),
 record_id TEXT NOT NULL CHECK(length(record_id)=64),
 locator_nonce TEXT NOT NULL CHECK(length(locator_nonce)=32),
 retention_policy TEXT NOT NULL CHECK(retention_policy IN ('6h','12h','24h','48h','no_expiry')),
 received_local_ms INTEGER NOT NULL CHECK(received_local_ms>=0),
 expires_local_ms INTEGER CHECK(expires_local_ms IS NULL OR expires_local_ms>=received_local_ms),
 request_key TEXT,
 CHECK((retention_policy='no_expiry' AND expires_local_ms IS NULL) OR (retention_policy!='no_expiry' AND expires_local_ms IS NOT NULL)),
 PRIMARY KEY(root_mailbox_id,object_id),
 UNIQUE(root_mailbox_id,body_object_id),
 UNIQUE(root_mailbox_id,record_id)
) STRICT;
INSERT INTO message_locators_v10 SELECT root_mailbox_id,object_id,body_object_id,record_id,locator_nonce,
 CASE lifetime_seconds WHEN 21600 THEN '6h' WHEN 43200 THEN '12h' WHEN 86400 THEN '24h' END,
 received_local_ms,expires_local_ms,request_key FROM message_locators;
DROP TABLE message_locators;
ALTER TABLE message_locators_v10 RENAME TO message_locators;
CREATE INDEX message_locators_expiry ON message_locators(expires_local_ms);
PRAGMA user_version=10;
COMMIT;
PRAGMA foreign_keys=ON;
