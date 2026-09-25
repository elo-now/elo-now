-- Existing message metadata has no access proof and cannot authorize refill or
-- early deletion. Ciphertext and historical evidence are preserved.
BEGIN IMMEDIATE;
ALTER TABLE message_bodies ADD COLUMN request_key TEXT;
ALTER TABLE message_bodies ADD COLUMN accept_key TEXT;
ALTER TABLE message_locators ADD COLUMN request_key TEXT;
DELETE FROM message_requests;
ALTER TABLE message_requests ADD COLUMN requester_credential TEXT;
ALTER TABLE message_requests ADD COLUMN proof_nonce TEXT;
ALTER TABLE message_requests ADD COLUMN proof_expires_ms INTEGER;
ALTER TABLE message_acceptances ADD COLUMN proof_nonce TEXT;
ALTER TABLE message_acceptances ADD COLUMN proof_expires_ms INTEGER;
PRAGMA user_version=9;
COMMIT;
