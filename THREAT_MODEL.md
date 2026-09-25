# Threat model

Document version: 0.5, 2026-09-25. This describes the trust boundaries and remaining limitations of the implementation. It is not a certification or a completed independent security audit. Claims on this page take precedence over marketing shorthand such as “complete E2EE” or “everything is auditable”. Source changes do not update already installed clients or deployed servers.

## Assets and trust boundaries

Protect signed event/file content, identity/device keys, history-export boundaries, provenance of approvals, and correct local state. A reading client process has plaintext and belongs to the trusted endpoint. The operating system and device holding an unlocked vault are inside the trust boundary.

An HTTP intermediary/Replica receives no age private keys. A node may observe IP addresses, mailboxes, sizes, frequency, connection times, and relationships between transfers of the same object_id. We do not guarantee anonymity, complete metadata privacy, or resistance to traffic analysis.

The controller is an explicitly trusted configuration administrator for one Space. This is separate from trusting infrastructure for ciphertext storage. Replacing a Replica does not remove the need to trust the chosen owners.

## Scenarios

| Threat | Expected response | Remaining limitation |
|---|---|---|
| Network eavesdropping | HTTPS for transport, age for content | Connection metadata remains visible |
| Malicious Replica | Local decryption, signatures, authority checks, and limits; no content keys at the Replica | It can omit data, lie in ACKs, and deny service |
| Modified/truncated object | Verify hash, complete age stream, and SignedRecord | No recovery without a valid copy |
| Substituted recipient keys | Root-signed credentials and trusted genesis/configuration | An incorrectly confirmed onboarding fingerprint still causes harm |
| Unauthorized SERVICE | No READ recipients for it in others' events; POST validation | It knows and can disclose its own input |
| Unauthorized history bundle | Current READ+SHARE_HISTORY, exact scope, original signatures, and limits | An authorized exporter can copy plaintext outside the protocol |
| Removed member | Hosted sends require a nonce-bound head confirmation, valid for at most 30 seconds and invalidated by known permission changes | Undelivered revocations have a bounded 30-second window; a compromised host can lie; standalone mode has no online attestation; old keys/content remain |
| Backdated event | Timestamp is not proof; first-seen stale record is quarantined | Without witnesses, the time of a historical signature cannot be proved |
| Command replay through history | Text-only export in v0.1; control proofs are read-only | IoT is not implemented |
| Forked signed configurations | Retain evidence and stop new domain operations | No automatic consensus/failover |
| Database/vault rollback | Pinned head, control-state check before outbox, separate restore flow | One malicious copy cannot prove globally latest state |
| Stolen device or age private key | Root-authorized permanent device revocation on every connected host; newly paired/recovered devices have independent signing and encryption keys | Recovery alone does not revoke anything; offline hosts may still be pending; existing copies and old shared credentials cannot be separated retroactively |
| Stolen HUMAN root | No root delegation to organizations; minimize retention | This profile cannot repair root compromise while retaining the same identity |
| Stolen controller key | Visible change audit and key isolation from Replica | The key can grant access within its role; administrative stop/recovery is needed |
| Malicious JSON/bundle/file | Depth/size limits, reject duplicate fields, no plugin execution | Implementation fuzzing and maintained libraries are needed |
| Quota/disk full | Reject before ACK; no silent GC | Destroying every copy removes availability |
| UI injection/log exfiltration | Escape text/ANSI, no payload HTML/JS, redact secrets | A compromised renderer can see displayed content |

## Invariants checked by tests

A Replica does not need content keys. Every event and approval has a verified signer and authority. POST does not imply READ. Ordinary joining does not deliver old content. A bundle discloses only approved originals, not automatically related history or file keys. Retry creates no duplicate. Original audience does not change after signing. Local commit is not remote approval. Historical control records are not executed.

Organization owners are explicit readers of their Streams. Their role does not grant takeover of another HUMAN identity. Operating a Replica server does not make its operator an organization owner.

## Guarantees we do not make

We do not prevent screenshots, copying, or deliberate sharing by an authorized person. We do not protect an unlocked compromised endpoint. We provide no ratchet, forward secrecy for retained objects, post-compromise security, or anonymity. This profile does not claim post-quantum resistance.

Revocation is not globally immediate during partitions. Audit means known verified evidence with state and uncertainty, not proof of completeness, true wall-clock time, or a person reading data. A signed receipt is a declaration, not proof of physical disk storage or the number of independent operators.

Hosted clients require a recent nonce-bound signed confirmation from their pinned Space host before encrypting a message, attachment descriptor or history grant. Ordinary Space status synchronization carries bounded batches of chat-head confirmations; unchanged General enrollment is not sent again. Confirmations are held only in the unlocked session, for at most 30 seconds measured from the request start. Cache hits never extend this deadline. A local General/chat head change, explicit device retirement or an authenticated record awaiting an unknown configuration invalidates the relevant confirmation. If no valid confirmation is available, one coalesced online check is required; failed checks back off for five seconds without granting access. The host checks the exact chat head and current device membership. A revocation not yet delivered to the sender can therefore leave up to a 30-second encryption window; this is an explicit availability/performance tradeoff. Once the confirmation expires, offline sends pause. This protects against a withholding storage Replica, not a malicious authorization host. Standalone laboratory mode has no online freshness authority; already encrypted or in-flight operations cannot be recalled.

Replica access v2 binds the pinned server key, configured public origin, exact method/path/query, body hash, transfer/retention headers, issuance time and a fresh nonce. A durable bounded nonce registry rejects reuse after restart. Pairing delegates a separate ephemeral signing key for ten minutes and one temporary mailbox only. Shared mailbox tokens are still not rotated automatically; hosted access requires both the token and an active device proof. Deploy matching clients and servers together; old request proofs are rejected.

Expired-message refill requires a signature made with a random secret inside the encrypted locator. DM early deletion uses a different secret available only inside the authenticated encrypted body, plus the peer's current credential. Proofs bind action, server, mailbox, object, original record, identity, device and deadline. The Replica rechecks current Space admission and device revocation before refill, and retries do not extend its five-minute window. The client verifies the original two-HUMAN Direct configuration and durably commits ACCEPTED before acknowledging. Capability possession does not prove a remote disk write or prevent authorized parties sharing keys/plaintext. Removal from a private chat alone is not a server-side revocation of a historical capability while that identity remains admitted to the Space; the Replica does not learn plaintext private-chat membership. Historical proof-less records remain locally readable but do not authorize refill or early deletion. This protocol update requires coordinated application/server deployment and device tests.

New root-code recoveries and pairings keep historical decryption keys but never reuse the old signing key. An unlocked, admitted device can sign revocation of another device belonging to the same identity after user confirmation; the host checks the signer and target. Revocation must reach every connected host. A durable host-wide tombstone survives Space deletion and prevents the retired credential from re-enrolling, deleting the account or obtaining new hosted content. Controllers update private-chat recipient lists; sending pauses until that update arrives. Losing the controlling device may require explicit controller recovery. Other hosts, previously issued notification capabilities, offline copies and legacy devices sharing one credential remain separate boundaries. Revocation does not erase historical plaintext or revoke the root recovery code.

Recovery material is a root credential: disclosure permits identity takeover. Password-protected recovery QR images and backups depend on the strength of their passwords against offline guessing. Device linking transfers profile secrets and the current password in an encrypted exchange after a QR scan and explicit Accept on the unlocked source. The QR contains a fresh secret that authenticates both parties and every transfer field; a source credential delegates one level of authority to fresh device keys. Conflicting requests permanently invalidate that link before approval, including requests discovered when confirming. A bounded inventory overflow also invalidates the link instead of silently hiding contenders. Someone who photographs the QR knows that secret and can request pairing or interrupt it; restart with a private, fresh QR. This does not protect approval of an unchecked device or compromise of the unlocked source.

New native recovery-code copying requests sensitive clipboard handling and expiry after 60 seconds. iOS uses a local-only pasteboard item with OS-managed expiry. Android and desktop clear an item only while it still appears to be the copied recovery code; Android retries expired cleanup on resume if background clipboard access was denied. Desktop cleanup depends on the running process, and OS clipboard history or third-party tools may retain copies. These are exposure reductions, not a guarantee that copied secrets can be recalled. No general renderer clipboard-reading command is exposed.

The native attachment interface issues session-scoped file handles. Renderer code cannot select arbitrary upload or download paths through that interface, and generic operations are explicitly allowlisted. This reduces the impact of renderer compromise but does not make a compromised renderer safe: it can still access the unlocked application's permitted operations and displayed content. Files saved by the user are outside the encrypted vault. New native saves set macOS quarantine or Windows Mark-of-the-Web metadata and report failure if the destination cannot retain it. These labels do not scan content or prevent the user from opening it; Linux has no equivalent implementation here.

Space creation requires signed-request-bound proof of work, persistent identity/network/deployment quotas and a bounded provisioning queue. Pending enrollment and upload slots, separate push-registration budgets, bounded call-proof workers, and cleanup of expired metadata limit resource exhaustion. Shared IPv4 addresses and IPv6 /64 networks share a creation budget. Space administration uses individually encrypted SQLite rows and an authenticated manifest; loading still checks the entire bounded state. An operator can restore an entire old database, so this is not protection against whole-server rollback. They do not prove that a new identity represents a different person. Persistent authorization floors are retained to prevent rollback; they still require a finite disk budget. Operators must set quotas appropriate to their storage and enforce proxy, firewall and TURN restrictions. Push wakes require a signed device proof. The recipient publishes per-chat credential allowlists with ordinary synchronization; the relay checks them at enqueue and delivery and removes queued work after revocation. Notify keys rotate with authorization reductions and blocking. Unknown scopes/unrecognized introduction senders share a durable five-minute quiet-hint budget and one queue slot per recipient, rather than being trusted as audible conversations. These policies take effect after synchronization and relay acknowledgement; an offline recipient may still have stale relay policy, and provider-accepted notifications cannot be recalled. No per-message membership request is added by this mechanism.

Calls expose connection metadata to the signalling and media infrastructure. Direct connections also expose network addresses to the peer. Push providers process device tokens and delivery metadata. New iOS VoIP registration requires production Apple App Attest and a fresh assertion generated over the native PushKit token, recipient account, route, server and challenge. The relay persists increasing counters and consumes challenges atomically. This trusts Apple's attestation service and the signed native implementation; it does not make a compromised operating system safe. The new client and relay require coordinated rollout and physical-device acceptance; older deployed builds do not provide this guarantee.

Biometric unlock stores an independent random wrapping key in the platform-protected item, with the password encrypted in a profile-bound local envelope. Changing enrolled Apple biometrics invalidates the stored item. Android uses an authentication-required key and a CryptoObject. A previously unlocked process remains trusted; locking the phone alone does not end that session. A full application process restart still requires profile unlock.

New iOS source builds exclude application data from system backups before opening
a profile, use after-first-unlock file protection to support background calls, and
cover inactive task previews. Android excludes OS backups and stores temporary
camera captures in private cache, cleaning them after use/restart. These controls
do not revoke explicit exports or copies made by an already compromised device.
Native behavior still needs acceptance on the target OS/build.

The release-policy check runs in the background against the configured HTTPS service with a bounded response. It never blocks local profile startup. A required update restricts new network operations and shared edits while preserving access to local history, with a persistent notice under the header. An unavailable endpoint does not create a requirement; a valid cached requirement survives an outage until replaced. The gate is not authorization or proof of the installed binary: a modified client can bypass it. A compromised policy server can restrict online operations, but cannot replace the local application or install arbitrary code. Maintain server-side verification and follow the [compatibility rollout](docs/API_COMPATIBILITY.md); already installed releases cannot gain this gate remotely.

Password-encrypted exports use scrypt work factor 17 (approximately 128 MiB).
New export passwords must pass a bounded local guessability check; this cannot
guarantee user-chosen entropy. Imported archives are capped at factor 18 to reject
hostile memory costs. Existing local vault unlock remains compatible with earlier
costs. Strong recovery secrets are still required against offline guessing.

Conservative quarantine may hold a valid delayed event. Peers may have different admission histories until an agreed history import. Increasing a configuration number does not repair missing data or keys.

## Deferred areas requiring a new threat review

Social recovery/guardians, automatic controller failover, multi-organization Spaces, automations with external effects, IoT commands, SSO/SCIM and confidential search remain deferred. Implemented mobile notifications, calls, attachments, retention and recovery require their own security validation; passing the original object-profile tests does not certify these later features. The device-revocation, fresh-head and server-bound proof changes require a coordinated client/server rollout and device acceptance tests. Signed configuration checkpoints are implemented locally with bounded ancestry and durable rollback/recovery floors; the recovery/adoption exchange has passed a physical-device QA scenario, while production rollout remains pending. Automatic controller failover remains deferred.

Explicit root recovery is implemented in the [authority module](crates/elo-core/src/authority/recovery.rs) and [bounded application exchange](crates/elo-core/src/app/control_recovery.rs). The original controlling owner's card can establish a new credential based on an approved checkpoint. Theft of that card can therefore lead to administrative takeover of its Space. A stale checkpoint may omit later revocations, so explicit membership review is required. The certificate neither erases the old device nor stops offline clients. Two conflicting root recoveries stop operations after both become known; the absence of automatic resolution is a deliberate availability limit.

The [checkpoint implementation](crates/elo-core/src/authority/checkpoint.rs)
reduces current-state authorization proof size without discarding local history.
A signed checkpoint is an assertion by the trusted current controller, not proof
of network-wide freshness. The service also retains a root-recovery floor so a
revoked controller cannot restore authority by inventing ancestor hashes.
Native recovery requires exact membership review and a profile password; only
the original owner supplies the root recovery code. Participant adoption remains
explicit. The exchange does not transfer hosting primary ownership or recreate
missing decryption keys.

See [core adversarial tests](crates/elo-core/tests), [call-service tests](crates/elo-call-service/tests)
and [deployment boundaries](docs/API_COMPATIBILITY.md). Test success does not
replace independent assessment or physical-device acceptance.
