# Initial migrations

`001_client.sql` and `001_replica.sql` are alternatives for **two separate databases**, not consecutive migrations of one database. Apply each once to an empty database of the appropriate role. `user_version=1` identifies the schema version, not the process type. Later client migrations are described in [STORAGE](../docs/STORAGE.md).

Before migration and after opening each connection, the application sets `foreign_keys=ON`, `journal_mode=WAL`, `synchronous=FULL`, and `busy_timeout=5000`, then reads them back. Do not change journal_mode inside a transaction. SQLite must support STRICT tables. `rusqlite` uses the bundled version recorded in Cargo.lock.

The application verifies hashes/bytes before INSERT and does not use `INSERT OR REPLACE` for immutable objects. A conflict on a particular PRIMARY KEY requires comparison with the existing object; other constraint failures must not be ignored. Tests use explicit `ON CONFLICT(...) DO NOTHING` clauses.

Local send writes the object, record, source, and all initial outbox targets in one transaction. Cryptography and HTTP remain outside it. Bundle import validates everything before one transactional import of originals and their sources. `source_index=-1` denotes the SignedRecord itself; 0..99 denotes an item in a bundle selection.

A Replica checks per-mailbox quota in the same transaction as the write; an existing delivery does not count as another copy. A separate global quota and concurrency limits protect disk and RAM. Schema CHECK constraints do not replace an HTTP limit before allocation. After restoring a backup, a node generates a new storage_generation before accepting traffic.

`receipt_record` holds a signed node declaration without message plaintext. Signature validation and mailbox/object/peer binding belong to the domain layer, not the database. The client database does not contain plaintext client tokens; the protected vault is separate.

Executed checks: [VALIDATION](../docs/VALIDATION.md). The initial schema alone does not constitute a complete protocol or backup system; subsequent work adds state such as durably consumed invitation IDs.

`002_replica_mailbox_delegation.sql` upgrades the recognized Replica v1 schema to v2, adding bounded parent/child mailboxes. The Replica verifies the existing schema before migrating and preserves its receipt key, generation, objects and deliveries. Back up a stopped instance before upgrading; an old v1 binary cannot open the upgraded database. Delegated bytes count against all ancestor quotas; expiry does not delete stored data. See [transport](../docs/TRANSPORT.md#delegated-mailboxes-for-invitation-delivery).
