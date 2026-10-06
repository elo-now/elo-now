# Membership and authorization

The authority chain determines permitted readers, posting devices and configuration
administrators. Storage acknowledgments and successful decryption alone do not
grant membership. This document describes current source behavior, not proof of
the state of a particular deployment.

## Anchors and authority versions

`SpaceGenesis` binds the initial owners, their root keys and the initiating
controller credential. Its signed record ID is the authority's `space_id`.
Version 4 also binds the independently provisioned witness pin. A user-facing
hosted Space contains General plus private conversation authorities; ownership
of General does not imply readership of every private conversation.

| Version | Administration |
| --- | --- |
| 1 | Root-signed genesis and a single active controller |
| 2 | Device-signed owner-managed General; a previously admitted owner device signs each update |
| 3 | Device-created private authority with one initial owner and single-controller rules |
| 4 | Device-signed initial General; later configurations are witness-signed and carry independently verified owner or admission evidence |

See [the protocol overview](../PROTOCOL.md#authority-versions-and-hosted-general)
and [authority validation](../crates/elo-core/src/authority.rs). These are authority
versions, not application release numbers or the version of every message record.
Existing genesis and old keys are not silently migrated.

The administrator can grant access within that authority; this does not let them
recover another member's identity root. Single-controller authorities have an
explicit root-authorized recovery path with checkpoint review. Owner-managed
General can instead use several independently admitted owner devices. A surviving
owner device can revoke a lost one and authorize a replacement. Importing an old
backup alone does not activate management. There is no automatic failover or
recovery after losing every admitted owner device in owner-managed General.

The primary owner of version-2 and version-4 General is the creator identity in
the verified genesis, not an editable role in the hosting database. It cannot be
removed or transferred. A change to the set of owner identities must be signed
by a currently admitted device of that primary identity. The same signature is
required to change the primary owner’s devices or capabilities. Co-owners may manage
ordinary members, but cannot promote, demote or remove owners. Before deleting
their own account, a co-owner must have the primary owner remove their owner
role; a primary owner must delete their Spaces first.

Authenticated live pairing records device eligibility even when a Space is
unreachable. When that Space becomes reachable, fresh verified membership must
admit the exact paired device before management is activated. Eligibility alone,
an ordinary backup or a retired device cannot confer this authority.

## Configuration and capabilities

`StreamConfig` is a signed snapshot containing its version, nonce, Space/Stream,
sequence, previous configuration, controller credential, members, admitted owner
device IDs, and action evidence. Single-controller recovery and witnessed
transitions have distinct, validated optional evidence. A numeric sequence or an
unverified claimed actor is not authorization.

Credentials bind public device keys to an identity root, directly or through a
bounded same-identity delegation chain. Membership capabilities apply to an
identity; the credential list determines its approved delivery devices. Revoking
a delegation's parent does not retroactively revoke a child already independently
admitted to the authority.

Creating a new hosted Space is a separate gate. A directly authorized or paired
device may sign creation for its own identity, subject to the host's creator
allowlist, proof of work and quotas. The host validates the complete bounded
same-identity delegation chain and rejects creation if the signing device or any
ancestor has a device revocation recorded on that host. A paired device does not
gain admission or management rights in existing Spaces through this check.

| Capability | Meaning |
| --- | --- |
| READ | Eligible recipient of new content in this Stream |
| POST | May create permitted records; does not imply READ |
| SHARE_HISTORY | May approve a bounded history disclosure; also requires READ |
| MANAGE | Administration within the applicable controller/owner/witness rules |
| REPLICATE | Storage/transport role, outside the plaintext audience |

Configuration snapshots contain membership, not old message content. New membership
does not automatically unlock older ciphertext. An authorized history holder can
make a separately signed and encrypted bounded disclosure; see
[history validation](../crates/elo-core/src/history.rs).

## Updates, forks and freshness

Updates bind the expected current head, its successor sequence and evidence of
the permitted actor. Peers verify ancestry from a trusted anchor. Missing links
wait for proof; conflicting valid successors retain fork evidence and stop new
operations instead of selecting a timestamp winner. In single-controller
recovery, conflicting root certificates likewise cannot be resolved by a larger
counter. See [recovery validation](../crates/elo-core/src/authority/recovery.rs).

Current hosted synchronization imports signed configuration evidence. An
independent Replica cannot declare a new authority merely by returning a
snapshot. Hosted sends require session-local permission leases of at most
30 seconds from the request start; known head changes and retirement invalidate
them. Failed checks do not authorize sending, and cached success never extends
the lease. Offline sends pause after expiry.

For witnessed General, the native client obtains nonce-bound freshness directly
from its independently pinned witness and retains the highest observed journal
position. The API cannot renew that lease. Hosted private-chat operations also
require fresh General admission, but their own configuration changes are not
independently serialized by the witness. Baseline hosting without witness retains
its host-authority trust. See [membership checks](../crates/elo-core/src/app/membership.rs)
and [witness freshness](../crates/elo-core/src/app/witness_client.rs).

A 30-second lease is a bounded revocation delay, not instantaneous global
revocation. It cannot recall ciphertext already sent. Standalone clients lack an
online freshness authority, and modified clients can retain or disclose old
content. A signed message time is not proof that an old message preceded removal;
the authorization witness does not timestamp individual messages.

## Receiving and history

A locally verified current-head event can be accepted. Unknown configuration
waits for proof; a first-seen stale event is held rather than silently presented
as newly authorized. An event already accepted retains its history and provenance.
A locally pending send must not silently acquire a new audience after permissions
change: a new audience requires a new signed event.

A history grant is a new disclosure to current authorized readers, not execution
of old administration. It carries approved originals and bounded related author
actions. Former readers obtain no new grant, although keys and ciphertext already
received remain theirs. Early and late peers can therefore have different local
projections until explicit history transfer reconciles available content.

## Invitations and the witness boundary

Baseline version-2 General uses expiring bearer invitations known to the host and
requires a live owner device to commit enrollment. Approval-required requests do
not acquire membership while pending. An operator who knows an open bearer token
can request ordinary admission under that baseline policy.

Version-4 General registers an owner-signed policy with the independent witness.
A short invitation contains a fragment seed; the API stores the encrypted,
owner-signed descriptor and receives only its identifier on retrieval. Native
clients verify the descriptor against their separately configured API origin and
witness pin. The URL cannot install a new trust anchor.

Admission proves possession of both the invitation key and the candidate device
key, binds the signed contact and a fresh challenge, and obeys expiry and usage
limits. Approval-required admission and readmission additionally need explicit
owner approval. An ordinary open invitation grants Read and Post only and can be
used while the owner is offline. Every later configuration verifies its embedded
owner or admission evidence as well as the witness signature.

A copied full link is still a bearer capability. API-only compromise can deny
service or observe metadata but does not supply the fragment seed from encrypted
descriptor storage. Compromise of an endpoint, invitation secret, owner key or
witness remains a distinct threat. The witness is not a universal private-chat
administrator or a message-decryption service. Its sealed restart, independently
retained journal position and shared-provider limitations are described in the
[deployment guide](../deploy/witness/README.md) and [threat model](../THREAT_MODEL.md).
