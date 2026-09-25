-- Replay protection survives service restarts. Unexpired entries are never evicted.
BEGIN IMMEDIATE;
CREATE TABLE access_nonces (
 credential_id TEXT NOT NULL,
 nonce TEXT NOT NULL,
 expires_at INTEGER NOT NULL,
 PRIMARY KEY(credential_id,nonce)
) STRICT;
CREATE INDEX access_nonces_expiry ON access_nonces(expires_at);
PRAGMA user_version=8;
COMMIT;
