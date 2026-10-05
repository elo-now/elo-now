# Message retention and retrieval

Three independent policies apply: a Space's Replica body lifetime, a sender's
**Keep** deadline, and attachment expiry. This is the current implementation
contract, not a claim that every previously distributed build enforces it.

## Sender-selected Keep deadline

The composer offers **Keep: ∞ / 1h / 24h**, default **∞**. The message menu and
Keep dialog use **No expiry / 1h / 24h**. A duration starts at native send time;
`payload.expires_at_ms` is signed inside the encrypted message and its locator.
Previously created 12-hour deadlines and expiry actions remain valid wire values.

Before expiry or deletion, the author can change or remove the deadline through
a signed `chat.action` of type `expiry`. A new duration starts at that action's
signed logical time. Clients project author actions in deterministic order;
actions at or after the effective deadline cannot reopen the message, and other
participants cannot change it. Original signed bytes remain unchanged.

Messages and replies have **independent deadlines**. Expiring the parent does not
expire its replies, and a known expired parent can still anchor a new reply.
The reply composer retains the same Keep controls.

At the deadline, updated clients show **Message expired** while retaining the
author, time and thread position. The projection applies to history, threads,
search, pins and unread activity, including late delivery and restart. Expired
text is excluded from new history grants and an expired locator cannot start
Retrieve. Pending notification targets are bounded by the effective deadline.

Keep is an application visibility rule, not verified erasure from every device,
signed record, backup or exported copy. It does not replace the Replica policy.
See [message actions](../crates/elo-core/src/app/message_actions.rs),
[record validation](../crates/elo-core/src/record.rs).

## Replica body lifetime

At Space creation, the owner chooses **6 / 12 / 24 hours**, default **24 hours**.
The duration measures elapsed time from the server's original receipt of a
classified message body, not from the message's claimed display timestamp.
The current interface does not change this setting on an existing Space.
Legacy descriptors without this policy retain their separate manual cleanup path.

Replica is temporary delivery storage. Expiry removes the body ciphertext;
devices retain history they already accepted. A separate signed, encrypted
locator remains available to the original admitted recipients so an offline
device can discover a missing message in the correct conversation. Joining later
does not grant keys to old locators. Genesis, authorization state, membership,
logs and backups have different lifecycles; they are not all erased at 24 hours.

If a device stays offline longer than the body lifetime, retrieval can require
another current member's device with a copy, online with elo open and the profile
unlocked. If no usable copy or key remains, the message cannot be recovered.

### Earlier deletion in one-to-one DMs

A Direct conversation with exactly two HUMAN identities can drop its body earlier:
a device of the **other identity** must decrypt the complete body, verify its
signature and authority, and durably commit it as ACCEPTED before acknowledging.
One device is sufficient; another device of that same identity may subsequently
need Retrieve. Acceptance by the author's own device does not qualify. Group DMs
and ordinary chats use the Space lifetime.

The acceptance additionally proves possession of a random secret from inside the
encrypted body, independent of the locator's retrieval secret. The Replica checks
that proof, the intended peer, current Space admission and credential revocation.
A locator-only download or ciphertext storage does not authorize deletion.

This is not a human read receipt. The server verifies capability possession, not
a remote disk write, and cannot prevent an authorized party from sharing a secret
or plaintext. Acceptance retries are idempotent and cannot delete a later refill.

## Locators, Retrieve and refill

Locators contain no message text. They bind the signed original, body object and
conversation and contain a random retrieval secret inside encryption. Public
ownership/retention envelopes also expose the originating credential, object and
record identifiers, and public verification keys. Infrastructure therefore still
sees operational metadata, sizes, timing and relationships; an encrypted locator
is not an anonymity mechanism.

A missing body appears as **Message unavailable** with **Retrieve**. While waiting,
the action becomes **Retrieving…**. A successful retrieval verifies the original
bytes and places the same signed record in that position. The placeholder itself
is not accepted message content or proof that the message was read.

Retrieve requires an authenticated current device and a capability signature from
the locator secret. The proof binds operation, pinned Replica, mailbox, object,
original record, identity, credential, nonce and deadline. Object IDs or new Space
membership alone cannot authorize old-content retrieval. Removed members, deleted
accounts and revoked credentials cannot keep an active request.

A holder may refill only the **exact original ciphertext** and only while a valid
request remains open. Both holder and requester must still be admitted; the
Replica rechecks the requester before advertising the request or accepting a
refill. Ordinary repair cannot silently re-upload an expired body.

The server request window is at most **five minutes from first admission**, also
bounded by the proof deadline. Proof validation permits two minutes of forward
clock tolerance without extending that five-minute grant. Repeated requests by
the same identity do not move its deadline. A refill remains only for the valid
window; a later explicit Retrieve can open a new window with a fresh proof.
Request nonce records can remain until their signed deadlines for replay control.
One valid refill serves concurrent authorized requesters; each need not upload a
separate body.

**Known timing limitation:** the current UI waits up to **55 seconds**, while
full synchronization with realtime connected can be **60–61 seconds** apart. A
failure dialog can therefore precede an available holder's next synchronization.
That timeout is not proof that nobody is online or that no copy exists, and the
five-minute server window may still be active. The dialog explains that another
device with a copy may need to be online, open and unlocked. Dedicated background
wake of holders solely for Retrieve is not implemented.
See [the UI timer](../apps/desktop/src/UnavailableMessage.tsx) and
[sync scheduling](../apps/desktop/src/liveSync.ts).

## Quota and maintenance

The supplied hosting configuration uses a **150,000,000-byte** message quota per Space. Bodies, locators,
control records and retention metadata share it; deleting bodies does not remove
all storage growth. Each body, locator, request and acceptance row reserves a
conservative 1024-byte metadata allowance in addition to ciphertext.

| Item | Retention |
| --- | --- |
| Message body | Space lifetime, or eligible one-to-one peer acceptance |
| Locator | 30 days from the locator's first server receipt |
| Active retrieval request | At most five minutes; replay metadata until the signed deadline |
| Refilled body | Until its valid request window ends |
| Acceptance retry metadata | At most 24 hours |
| Body-absence metadata | Associated locator lifecycle |
| Authorization, admission and invitation state | Their own protocol lifecycle; not sacrificed to make room for messages |

Maintenance reclaims expired bodies, ended refill windows and expired metadata,
then performs bounded SQLite reclamation/checkpoint work. It does not shorten a
live message's configured lifetime or delete authorization records to admit a new
upload. If live data still fills the quota, uploads fail with storage-full status;
durable pending local sends remain available for retry. Old backups and external
copies remain separate retention boundaries.

The [Replica retention implementation](../crates/elo-core/src/replica/retention.rs),
[message capability proofs](../crates/elo-core/src/retention_access.rs),
[retention tests](../crates/elo-core/tests/retention.rs) and
[access tests](../crates/elo-core/tests/message_access.rs) define these checks.
Deploy matching applications and services: earlier identity-only requests are not
accepted as a fallback when current capability proofs are absent. Historical
records can remain locally readable without authorizing refill or early deletion.

## Attachment expiry is separate

Attachment policy offers **1 / 12 / 24 hours**, default **1 hour**, for new uploads.
Expired provider objects become due for deletion; failed deletion is retried, so
physical removal can lag. Downloaded encrypted caches or explicit exports can
remain on recipients' devices. The message body lifetime and Keep setting do not
stand in for this policy. See [attachments](ATTACHMENTS.md) and the
[storage broker](../crates/elo-storage/README.md).
