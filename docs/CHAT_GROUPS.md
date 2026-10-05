# Personal chat groups

The first system view uses an icon with two overlapping chat bubbles, replacing the previously selected Yo label. Its accessible name is **Recent and ungrouped chats**. The horizontal group strip starts with this icon, then **DMs**, followed by the user's custom groups in creation order. These two system views are filters, not assignable groups.

- The first view displays **Recent** (up to five most recently active chats), then **Ungrouped** (remaining chats without a custom group). Do not repeat a Recent chat in Ungrouped. Older grouped chats remain available under their group.
- Recency uses the newest valid message timestamp or the chat's local creation/import time. Missing or invalid dates are not treated as now. Signed timestamps are presentation inputs, not proof of a peer's clock or receipt by a person.
- DMs contains conversations explicitly created as **DM**, including a new conversation awaiting invitations, one-to-one DMs and group DMs. Creation always defaults to DM. A Lucide person icon identifies a one-to-one DM, multiple people identify a group DM, and a hash identifies a named Chat. Count distinct member identities, not devices. Adding/removing people changes the icon without changing the conversation type. A named Chat with two people remains a Chat. Type grants no membership or capabilities; all participants still enter through the existing approved invitation flow.
- The full-screen creation view changes its heading between **New chat** and **New DM** with the **DM / Chat** selector. Chat adds **Name** and optional **Group** to the shared known-person selection list, initially **None**. The adjacent **+** creates a group inline and selects it. A partially entered new group must be created or cancelled before submitting the chat. Opening from a custom group preselects that group. Both types select people with search and the shared compact checkboxes; DM requests neither name nor group. Its name is generated from the selected participants, and the existing organization action can assign the resulting DM to a private group later.
- An existing chat can be assigned, moved or ungrouped through **⋯ → Group → Save**. In that dialog, Group appears only in the heading; the select retains an accessible name without a repeated visible label. This changes organization only. Group rename/delete and multi-group assignment are not part of this change.

## Ownership and storage

The DM picker includes the current profile with a **Notes** label. Notes is one
private DM in the selected hosting Space, containing only that identity and its
explicitly admitted devices. Selecting it clears other recipients. Normal
message encryption, synchronization, retention and Space attachment storage
apply; message and session notifications exclude the sender's own identity.

The signed `notes` hosting command binds `general_head` and optionally carries a
complete private v3 authority proof and `expected_head` for updates. A bounded,
durable first-writer registry chooses one conversation per profile and hosting
Space. Clients verify the signed authority and its exact hosting-derived stream;
the registry does not grant membership. Concurrent creation returns the same
winner. Existing local authority pins reject rollback or replacement. Only the
Notes controller can change recipients, restricted to the profile's devices
currently admitted in that Space. General chat-permission publication cannot
bypass this registry, and Notes does not support adding other people.

Accepted devices can exchange new Notes messages without the controller being
online. Granting a newly paired device, or narrowing a revoked recipient set,
requires a signed update from the Notes controller. Until then, access fails
closed; pairing itself can finish without granting Notes. An interrupted grant
can be retried by the controller; a committed grant is imported without creating
another Notes conversation. Retiring the only Notes controller currently leaves
recipient updates unavailable; controller handoff is not implemented.

The existing device-copy format carries the parent's decryption history,
including its current encryption key. Removing a device blocks its authenticated
hosting and Replica access, but does not cryptographically prevent it from
reading later ciphertext encrypted to an inherited parent key if it obtains that
ciphertext elsewhere. This requires a separate pairing/key-rotation change; Notes
does not provide stronger revocation than the underlying device-copy format.
These changes require the corresponding clients and hosting service and are not
an upgrade of the frozen legacy deployment.

Groups are private to the user identity. Chat participants cannot see or inherit another user's organization. They are not chat membership groups, Space owners or Replica mailbox permissions. Group IDs are random 128-bit values; names and assignments live only in the encrypted local workspace, not signed chat/config records, invitation exports or Replica metadata. Normal message/config exports do not carry group assignments.

Workspace v3 retains groups and adds a persisted conversation category to each pin. Existing v1/v2 workspaces are upgraded after their encrypted authority snapshots are verified: a signed category takes precedence, otherwise an existing one-to-one human conversation is recorded as DM and other conversations as Chat. Save that legacy decision once so later membership changes cannot move the conversation between categories. Migration retains identities, vault bytes, signed records, group assignments, messages and unread state. Invalid categories, missing v3 categories, unknown workspace versions and the existing invalid group/collection cases are rejected. Older clients cannot read v3; use the upgraded clients together.

New conversations sign `chat_kind: "chat" | "direct"` into their first `stream.config`. Once present, it cannot be changed or removed by a later config. It travels with encrypted authority snapshots in invitation approvals, ordinary configuration import and controller recovery. A legacy controller publishes its persisted category when next creating or approving an invitation; its existing signed records are not rewritten. This is an ordinary configuration update with the existing stale-outbox handling. Signed metadata takes precedence over a recipient's old local category. It does not synchronize subsequent membership updates automatically, personal groups or account settings.

## Required account synchronization follow-up

Use the shared [private account settings synchronization](ACCOUNT_SETTINGS_SYNC.md) architecture for groups and future account preferences. Do not build a separate group-only synchronization transport. Read/unread markers, explicit thread following and new-message participation now use that private mechanism; group organization remains local.

The creator explicitly requires the same user's group organization to synchronize between desktop and mobile when device synchronization is available. The current implementation is a local encrypted copy and **does not synchronize groups yet**. Group persistence or message replication must not be reported as account-settings synchronization.

Account metadata synchronization must bind updates to the same verified user identity and authorized devices, encrypt them so other chat participants and Replica operators cannot read them, and support offline edits, deterministic conflict handling, deduplication, ordering and deletion without resurrecting removed assignments. Synchronizing a chat's group must never add a participant or grant access to that chat. Device enrollment/revocation and recovery need explicit tests before enabling exchange. Do not place plaintext group names in DNS/mailboxes, reuse shared chat messages as hidden settings, or distribute settings to all conversation recipients. The current stable group/Stream identifiers provide references; they are not a complete synchronization protocol.

Implementation lives in `elo-core/src/app/groups.rs`, the encrypted Workspace/Pin model, and shared `ChatOrganization.tsx`/`chatGroups.ts`. Both platforms use the shared frontend; behavior is covered by the [group tests](../crates/elo-core/src/app/groups/tests.rs) and [Notes tests](../crates/elo-core/src/app/invitations/personal/notes/tests.rs).
