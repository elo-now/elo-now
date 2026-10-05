# Private account settings synchronization

Status: read/unread markers, explicit followed/unfollowed threads and new-message thread participation now use the private synchronization mechanism below. Personal chat groups, profile details, mute and interface preferences remain local. Device linking also copies the encrypted local state; this is distinct from ongoing synchronization. This client implementation has not been deployed to the frozen legacy service or stores.

The creator requires a shared mechanism for private settings/data that belong to one user and should follow that user between desktop and mobile. Read state and thread preferences are the first synchronized consumers; chat groups already use a typed local model and remain a future consumer. Further candidates include the profile name/avatar, group/chat ordering, pinned chats and user-selected interface preferences. A new synchronized preference must use the common mechanism rather than adding its own network transport, separate identity rules or ad hoc conflict behavior.

## Implemented private read and thread state

Each joined hosting Space has a separate namespace derived from its verified
General authority and the user's identity. The transport is the existing Notes
conversation, whose signed authority contains exactly one HUMAN identity and
only its explicitly approved devices. It is not a hidden message in a shared
conversation. The hosting Notes registry selects an authority; it cannot choose
recipients or grant approval. Notes recipient updates still require its original
controller, and a missing approval leaves local edits pending rather than
bypassing it.

`chat.private-settings` is a dedicated signed record kind. Its encrypted payload
contains a version, identity, hosting scope and at most 32 typed mutations. It
cannot contain public text, mentions, reactions, expiry, thread content or a
message locator. Existing age encryption addresses only the verified Notes
recipient credentials. Replica storage receives ciphertext; private records are
excluded from message lists, unread counts, message wakes and notification
outboxes. The currently admitted sender, exact Notes namespace and hosting scope
are checked again before applying data. A root-issued credential alone does not
authorize this transport.

Mutations are keyed by kind, Space, stream and message ID. A bounded Lamport
clock and credential ID order concurrent changes deterministically; equal
stamps use a stable boolean tie-breaker. A checkpoint merges values rather than
replacing the local state. Duplicate delivery, reordering and delayed snapshots
cannot overwrite a newer explicit read/unread or follow/unfollow action. Clock
values are bounded by the existing signed-message clock-skew rules and only
currently authorized same-identity senders may supply state; timestamps alone
never authenticate a change.

The encrypted `read-state.age` persists values, coalesced pending keys, a separate
checkpoint queue and the receive cursor together with their local projection. It
retains the existing 14 MiB serialized metadata safety bound. There is no fixed 50,000-message cutoff.
The local v2 encoding interns repeated Space, stream and device IDs and stores
fixed 47-byte mutations plus bounded base64 framing. Queue membership uses flag
bits rather than repeated string keys. Seen/unread sets already represented by a
private mutation are encoded only once and reconstructed on load. This avoids
reducing the existing marker capacity; a 100,000-marker round-trip regression is
smaller than the equivalent legacy seen/unread JSON. The network batch stays v1.
Malformed counts, indexes, duplicate keys, unknown flags and trailing bytes are
rejected before adoption; historical JSON state still opens without migration loss.
Existing seen/unread markers for known chats are migrated once into a baseline:
historical seen uses clock 0 and explicit historical unread uses clock 1.
These baseline values cannot replace any fresh local or remote action, and the
historical unread marker wins when two legacy devices disagree. Older markers
for unavailable chats stay local because their Space cannot be bound safely.
Thread participation is recorded for new sends; the frontend also derives it
from already loaded verified historical messages.

Local actions perform no network calls. The regular synchronization worker first
receives chat data, then gives private transport preparation at most one second.
The normal durable Replica outbox handles upload retries and distinguishes queued
changes from stored ciphertext. Queue removal happens only after the local outbox
transaction commits; a crash between writes can duplicate an equivalent batch
but cannot lose it. Client schema v9 adds a monotonic local processing queue of
record IDs, including fresh queue positions when delayed permission evidence
admits an older record. Profile backups retain pending or unapplied private
events, their original queue IDs, and the sequence high-water mark. Already applied, fully stored checkpoint
events can be omitted because their merged state is in encrypted `read-state.age`;
repeating checkpoints therefore cannot alone exhaust the message-backup budget.
Changes apply atomically to the encrypted local projection before its cursor
advances. A missing Notes authority, configuration proof or encrypted
object leaves its cursor position pending; unsupported schemas and verified
invalid messages cannot block later valid changes.

A new Notes head or a six-hour checkpoint marks the retained current values for
republication in bounded batches. New local changes are sent before checkpoint
entries, so a large retained history cannot delay fresh read/follow actions behind
its older snapshot. This permits convergence after server retention
has removed prior batches, but a large history requires multiple synchronization
rounds and checkpoint traffic grows with retained settings. Immediate delivery
requires both devices to be running synchronization; suspended phones catch up on
resume. No public read receipts or extra notification wakes are sent for private
state. Native push reconciliation removes alerts for remotely read chats even
while another chat is still unread.

Revocation has the same boundary as Notes and device linking: revoked devices
cannot submit new state or use authenticated hosting/Replica access. An existing
linked-device copy can retain the parent's decryption history/key; this change
does not solve that pre-existing key-rotation limitation if later ciphertext is
obtained through another route. Retiring the only Notes controller still requires
a separate controller-transfer implementation before recipient updates can
resume. Do not describe this layer as stronger than its enrollment protocol.

Validation uses synthetic profiles and a local HTTP Replica/hosting fixture for
multiple approved devices, encrypted read/follow propagation, no additional chat
rows, controller-offline operation and persistence after restart. Focused tests
cover deterministic concurrent merge, duplicate/reordered events, durable offline
pending state, legacy-marker bootstrap, fresh-change priority over checkpoints,
late permission admission, unsupported schemas, revoked issuers, temporary missing
authority and selective notification cleanup.
No production messages, profiles or live service data are used by these tests.

## Scope classification

Conversation mute is now another local consumer: a typed stream-ID set inside encrypted `read-state.age`, defaulting to unmuted for older profiles and included in full backups. It suppresses Buzz and incoming-message banners, not message delivery/read state or explicit reminders. Future account-settings synchronization should carry this preference privately across approved devices; muting must never be encoded as a shared chat-membership change.

Each setting needs an explicit scope and schema. Account-scoped examples include personal group IDs/names, chat assignments and a private per-record seen set that can make unread state consistent across approved devices without exposing read receipts to chat participants. Device-scoped examples include local paths, cache limits, OS permissions and the actual biometric-unlock secret/configuration. Root secrets, recovery phrases, device signing keys, encryption keys, Replica tokens, biometric material and OS permission grants must never become generic synchronized preferences. A display preference may later have an account default with a deliberate per-device override; do not assume every setting should be copied automatically.

## Shared mechanism requirements

- Bind the namespace and every accepted change to the verified user identity and authorized devices. Another participant's chat configuration cannot modify this user's preferences.
- Encrypt and authenticate private settings end to end for the user's approved devices. A Replica remains a ciphertext store. Chat membership and settings ownership remain independent.
- Use stable entity/operation identifiers, explicit schemas and versioned migrations. Consumers such as groups should define typed data and mutations, while the common layer handles transport, persistence, verification and retries.
- Support local use and offline edits. Define deterministic conflict resolution, concurrent rename/assignment/order behavior and tombstones before enabling synchronization; retries must not duplicate groups or resurrect removed items.
- Persist applied changes, pending updates and synchronization checkpoints durably. Storage receipts, device adoption and an unresolved local edit need distinct meanings; a successful local save cannot imply synchronization to another device.
- Handle device enrollment, approval, revocation and recovery explicitly. A root-issued credential alone must not silently bypass the application's device-approval policy. Adding a device may grant settings access without granting membership to arbitrary chats referenced by those settings.
- Keep unknown newer schemas safe and preserve existing data. Verify upgrades, duplicate/out-of-order delivery, offline concurrent edits, revoked devices and process failure before advertising desktop/mobile settings synchronization.

Each additional consumer must document its relationship to existing HUMAN/device credentials, controller generations, encrypted storage and Replica delivery. The current group IDs and verified Space/Stream references can be retained; the group workspace file is not itself a completed synchronization protocol.

See [personal chat groups](CHAT_GROUPS.md) for the implemented local behavior and current migration.
