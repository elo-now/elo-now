# Protocol — signed objects and versioned authority

This document describes the implemented object format and its authority variants, not an independently audited production standard. The ELO1 envelope, individual record schemas and authority versions are separate version boundaries. Changes to accepted format bytes require explicit compatibility handling and updated fixtures; a new authority version does not renumber every message record.

## 1. Three distinct objects

A **SignedRecord** is the original signed record. An **EncryptedObject** is the age ciphertext containing it. A **Delivery** is the entry of a specific object in a specific recipient mailbox.

One record can appear in multiple encrypted bundles. Its record ID stays the same; ciphertext IDs may differ. Retrying a delivery sends the same stored bytes rather than encrypting again for each attempt.

## 2. SignedRecord: exact bytes

```text
B = UTF-8(JSON body)
S = Ed25519.Sign(device_signing_key,
                 ASCII("elo.now/signed-record/v1") || 0x00 || B)
R = ASCII("ELO1") || U32_BE(len(B)) || B || S
record_id = SHA256(ASCII("elo.now/record-id/v1") || 0x00 || R)
```

The signature is 64 bytes. R contains no extra bytes after the signature. `record_id` is not a field of B, avoiding a self-referential definition. The API displays SHA-256 as 64 lowercase hexadecimal digits. An event `nonce` is 16 random bytes encoded as 32 lowercase hexadecimal digits; two otherwise identical messages created separately have different nonces.

Verify **the retained B**, never JSON reserialized by the recipient. Producers generate compact JSON with stable field order for tests. Field order and whitespace are not globally canonicalized; a different encoding of semantically identical fields is a different signed record, not equivalent signature input.

Each JSON document is one UTF-8 object, without a BOM, trailing bytes, duplicate keys, NaN/Infinity, or unknown fields for its `kind`/`v`. B begins with `{` and ends with `}`; there is no whitespace outside the object. Strings must not contain unpaired surrogate code points. Controlled numeric fields are integers in 0..2^53−1. Maximum depth: 16. Serde structs and explicit duplicate-key checks must cover nested objects; parsing into a generic map alone is insufficient.

The validator checks length limits before allocation, then framing/JSON, the authorized key, signature, and semantics. Some checks may be reordered for efficiency, but no domain effect occurs before all validation succeeds.

## 3. Minimal message

```json
{
  "v": 1,
  "kind": "chat.message",
  "nonce": "<16 random bytes as hex>",
  "space_id": "<hash of signed SpaceGenesis>",
  "stream_id": "<16 random bytes as hex>",
  "issuer_identity": "<identity_id>",
  "issuer_credential": "<record_id DeviceCredential>",
  "config_id": "<record_id StreamConfig>",
  "audience": ["<identity_id>"],
  "recipient_credentials": ["<record_id DeviceCredential>"],
  "logical_time": 1,
  "created_at": "2026-09-08T12:00:00Z",
  "parents": [],
  "payload": {"text": "elo"}
}
```

This describes fields, not an executable fixture: angle-bracket values are metavariables. `protocol/fixtures/` contains an example with a real valid signature; its authority references are synthetic, so it is not a complete authorization fixture.

`audience` is a sorted, duplicate-free list of authorized HUMAN/SERVICE/DEVICE readers under the referenced configuration, including required owners. `recipient_credentials` contains the exact set of their approved devices plus the author's credential for a local self-copy. A post-only author's self-copy does not grant READ on other events. REPLICATE alone never places a Replica in these lists.

Normal-message recipients are derived from the configuration, not an arbitrary author-supplied list. The signed list documents intent; it does not prove that a modified client made no additional undisclosed copy.

`parents` contains at most 16 record_id values, optionally the last known dependencies. Do not automatically fetch parent content the recipient may not read. `logical_time` is for presentation order, not authorization or proof of real time. In the version-1 text schema, `created_at` is UTC `YYYY-MM-DDTHH:MM:SSZ`, a display claim rather than trusted time. `payload.text` is 1..16384 UTF-8 bytes. `recipient_credentials` is also sorted and duplicate-free.

New clients may include `payload.sender_name`, a self-selected display name of 1..120 UTF-8 bytes, without leading/trailing whitespace or control characters. Omission or null means no name claim. It is covered by the record signature and age encryption, never a plaintext transport header. It does not replace `issuer_identity` or grant trust/permissions. Within each chat, the latest verified name in canonical record order supplies the display label, including older messages by that identity. A local profile edit is shared with that chat on the next text message; it does not rewrite old signed bytes or distribute avatars. Legacy records remain valid and unchanged. Older strict clients reject this new payload field, so use upgraded clients together.

`payload.thread_root` optionally names the original text message or file announcement by canonical `record_id`, within the same space/stream. Omission or null means an ordinary top-level message. It is signed/encrypted with the text, separate from causal `parents`, and grants no access to the referenced record. The application resolves a reply-to-reply to the original and allows only one thread level. Receivers retain otherwise authorized replies whose original has not arrived; they never fetch/disclose inaccessible history implicitly. Unknown, cross-chat or nested references must not be followed into another conversation or treated as authorization. Explicit history import may later attach the original. Older strict clients reject this field; upgrade participants before sending replies. See the [record validator](crates/elo-core/src/record.rs) and [message actions](crates/elo-core/src/app/message_actions.rs) for current bounds, edits and expiry. Replies have their own expiry settings; the parent's deadline does not implicitly delete them.

## 4. Encryption and object identity

```text
C = age_v1_encrypt(pack(R), approved_device_public_keys)
O = C, or the supported signed ownership envelope containing C
object_id = SHA256(ASCII("elo.now/object-id/v1") || 0x00 || O)
```

The message payload uses bounded, versioned per-record packing before age; it retains raw signed bytes when DEFLATE would not reduce the payload. Decompression is bounded and restores the exact signed record. The result is binary age without armor or a plaintext channel name; the Replica does not recompress ciphertext. See [the packing implementation](crates/elo-core/src/crypto.rs). Current hosted message bodies and locators use the [signed ownership envelope](crates/elo-core/src/erasure.rs), whose public claim binds the uploader credential, ciphertext hash and supported deletion/retention metadata. The whole stored object, including that envelope when present, is hashed. The wrapper exposes operational identifiers and public retention-verification keys, not message plaintext or the private capability secrets. Legacy unwrapped objects remain a distinct accepted format. Mailbox identifiers, lengths and traffic remain visible to infrastructure. The library implements age; elo.now does not.

Messages use long-term recipient keys. Fresh age file keys do not provide a messaging ratchet, forward secrecy for retained objects or post-compromise security; see [CRYPTOGRAPHY](CRYPTOGRAPHY.md).

All information needed to interpret an event is signed inside R. A conforming client checks its own membership in the audience/credential lists; successful decryption alone is insufficient authorization.

## 5. Record kinds

| `kind` | Signer | Effect |
|---|---|---|
| `device.credential` | Identity root, or a bounded same-identity device delegation | Binds device keys; alone grants no Stream access |
| `space.genesis` | Identity root in v1; authorized initiating device in v2–v4 | Anchors the authority and its initial owners/controller; v4 also pins the witness |
| `stream.config` | Active controller, admitted owner device, or witness with validated evidence, according to authority version | Next configuration of a Stream |
| `space.controller.recovered` | Root of the original controlling owner | Explicitly establishes a new controller generation without changing the Space |
| `chat.message` | Authorized device | Text message |
| `chat.action` | Authorized device, with action-specific author checks | Edit, deletion, expiry, reaction or pin projection; original bytes remain immutable |
| `chat.locator` | Authorized device | Encrypted reference and retrieval capability for an expiring message body |
| `history.access.requested` | Current reader | Request for an approved scope |
| `history.access.granted` | Current READ+SHARE_HISTORY holder | Manifest and content of a new history bundle |
| `file.body` | Authorized publisher | Legacy Replica-backed file resource; new clients do not create it |
| `file.shared` | Authorized publisher | Metadata and descriptor for an encrypted external attachment |
| `storage.receipt` | Storage endpoint | Storage declaration, not membership or reading |

This table summarizes the content and authority records, not the complete service-command registry. Witness policy, admission, receipt and freshness records are defined in [the witness protocol types](crates/elo-core/src/witness.rs) and [authority evidence validation](crates/elo-core/src/authority/witness.rs). Unknown kinds must not execute operations. An unknown security version is rejected as `UNSUPPORTED_VERSION`, not interpreted by resemblance. Generic SERVICE/DEVICE types remain in the identity schema; their application-event registry is extended separately.

## 6. Event state — more than a misleading sent flag

Local states:

```text
LOCAL → READY_TO_SYNC → REPLICATING → REPLICATED
                ↘ HELD_STALE_CONFIG
received ciphertext → WAITING_FOR_PROOF / ACCEPTED / QUARANTINED / REJECTED
```

REPLICATED means a selected storage goal has been met, not that everyone received the message. Delivery information is a separate set per peer/mailbox, not the end of an event's life. No human read receipt is implied. A verified, durably accepted one-to-one DM can trigger early body deletion on the Replica; that acknowledgment is still not proof that a person read it. See [retention](docs/REPLICA_RETENTION.md).

The event and its outbox form one local transaction. Network errors leave content in history with a pending state. A disk error before commit means local send did not succeed; the UI must not claim otherwise.

Do not change the signed audience during retry. A `resend` after a permission change creates a new event/nonce; the original remains locally unsent/held. This is a new user decision, not a silent repair of an old signature.

## 7. Receiving and deduplication

First check the hash of C, successful completion of decryption, and plaintext limits. Verify R's format, signature, and credential. Fetch only required authorization proofs through a bounded queue. Check Space/Stream/configuration and the current admission rule in [AUTHORIZATION](docs/AUTHORIZATION.md).

Application deduplication uses `record_id`. Receiving the same R again is a view no-op and may generate another ACK. The same claimed ID with different bytes is an integrity error, not an `UPDATE`. Different ciphertext containing the same R does not create a second message.

Unauthorized writes are rejected locally. A Replica storing ciphertext does not imply that the private record was valid.

## 8. Ordering without consensus

Presentation uses deterministic order `(logical_time, issuer_credential, record_id)`. Explicit dependencies help show causality but do not establish a globally confirmed time. The UI may reorder items after synchronization. Edits, reactions, pins, deletions and expiry changes are separately signed actions interpreted as a projection over retained originals; they do not overwrite the original signed record. Collaborative document editing is not implemented.

Each Stream's configurations form a signed chain of successive versions. Two
valid conflicting successors are not resolved by timestamps. The accepted signer
and transition evidence depend on the authority version.

### Authority versions and hosted General

| Authority version | Genesis signer | Later configuration authority |
| --- | --- | --- |
| **1: original single controller** | Initiating identity root | Active controller; explicit root-authorized controller recovery is a separate transition |
| **2: owner-managed General** | Initiating owner device | An exact owner credential admitted in the parent configuration |
| **3: device-created private authority** | Initiating device, bound to its identity root | Single-controller rules, with the creator as the sole initial owner |
| **4: witnessed General** | Initiating owner device, with the independently provisioned witness pin | Witness signature plus validated owner-proposal or restricted admission evidence |

`chat.message` continues to use its version-1 record schema in all these authority
variants. Version 1 is not shorthand for all current messages being on legacy
hosting. Clients do not silently convert an existing genesis or revoke old keys.

Single-controller recovery establishes a new generation over an approved
checkpoint. Its first configuration embeds the root-signed
`space.controller.recovered` certificate and is signed by the new device. Later
configurations inherit that credential. Old branches are preserved, and
conflicting root recoveries stop operations. See the
[recovery validator](crates/elo-core/src/authority/recovery.rs) and
[checkpoint validator](crates/elo-core/src/authority/checkpoint.rs).

New hosted creation selects version 4 when the client has an explicitly
provisioned witness, and version 2 in the baseline deployment without one. The
host validates the matching creation authority and rejects incompatible creation
requests before provisioning. Both owner-managed variants start with only the
real owner as a reader. Their public-only hosting service signs responses but is
not a General participant and holds no General decryption key. This does not
remove the enrollment-service reader from existing legacy version-1 General.

Owner-device delegation must be justified by the active parent and a bounded
credential chain. Approved live pairing admits the independent new owner device
before exporting the encrypted profile copy. A surviving admitted owner device
can revoke a lost device and authorize a replacement. Ordinary backup restoration
remains a follower and cannot acquire management just by loading an owner roster.
Versions 2 and 4 reject single-controller root-recovery/checkpoint formats;
recovery after losing every admitted owner device is not implemented for them.

In version 2, a live owner device commits membership after checking signed
administrative intent. The host serializes proposals against the expected head.
Open invitation tokens are bearer capabilities known to that host; its operator
can request admission as a token holder. Owner approval provides a distinct check.

In version 4, the witness serializes changes and clients also verify their embedded
evidence. An admitted owner can register an invitation policy with expiry, usage
limits and an approval requirement. Open admission needs signatures from both the
invitation key and candidate device, a fresh witness challenge, and a signed
contact. Approval-required admission and readmission additionally need owner
approval. This admits ordinary readers/posters while the owner is offline without
giving the API an invitation private key or authority to invent an owner decision.

The short `https://elo.now/join#...` link carries a ciphertext identifier and a
secret seed in its fragment. The API stores a bounded encrypted owner-signed
descriptor; clients use the seed locally to decrypt it and derive an admission
key. Only the ciphertext identifier is sent for retrieval. A descriptor cannot
supply a new trusted witness or API origin: both must match native provisioning.
Possessing the full link remains a bearer capability; encryption does not make a
leaked invitation safe. See [the codec](crates/elo-core/src/witness/link.rs).

Native clients obtain nonce-bound freshness directly from their pinned witness,
with a maximum 30-second lease and a persisted observed journal floor. The API
cannot renew that lease. Private-chat authorities remain separate: their hosted
operations also require fresh General admission, but the witness does not sign
every private-chat configuration. Offline sends pause after permission leases
expire. Witness-host compromise, shared provider control and coherent rollback
need the protections and independent activation evidence in the
[witness deployment guide](deploy/witness/README.md).

## 9. Attachments

New clients publish a `file.shared` record containing encrypted metadata and a provider-neutral attachment descriptor. The descriptor binds an opaque attachment/object ID, filename, MIME type, plaintext and ciphertext sizes, retention time, chunked-encryption parameters and the whole-ciphertext digest. The plaintext file limit is 5 MiB. Binary bodies are never embedded in a signed record or uploaded to Replica.

The client encrypts each body independently with chunked XChaCha20-Poly1305. In a broker-enabled deployment, the owner configures a scoped MEGA folder or S3 bucket directly with the separate storage broker; the Space API does not receive those provider credentials. The broker verifies General authorization and streams ciphertext without file decryption keys. The baseline Space-gateway provider path remains separate. A broker-host compromise can still expose its provider credentials or delete storage within their scope.

Downloads verify the signed `file.shared` record, applicable access checks, the ciphertext digest and every authenticated chunk before presenting a complete file. A bounded encrypted local cache avoids repeated downloads. Supported image previews appear in the conversation; explicit sharing/export and other files use native platform actions. Provider configuration is not included in recipient message descriptors. See the [broker contract](crates/elo-storage/README.md).

Backups and history metadata contain `file.shared` but exclude attachment bodies. Restoring a reference does not restore the body; it can be downloaded only while the server copy remains available and current membership permits access. The legacy Replica-backed `file.body` parser remains bounded but new clients do not create those objects. The complete current contract, retention rules and quotas are in [ATTACHMENTS](docs/ATTACHMENTS.md).

## 10. Further reading

[Authorization](docs/AUTHORIZATION.md), [cryptography](CRYPTOGRAPHY.md), [retention](docs/REPLICA_RETENTION.md), [history-bundle validation](crates/elo-core/src/history.rs) and the [Replica implementation](crates/elo-core/src/replica.rs) define the related boundaries. [Core tests](crates/elo-core/tests) and [witness tests](crates/elo-witness/src/engine/tests.rs) provide reproducible checks; their presence is not a claim that a particular deployment has passed them.
