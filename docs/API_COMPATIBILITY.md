# API compatibility and application updates

**Status: next-release work, not a feature of release 1.0.0.** The policy endpoint
and client gate described here have been implemented and tested in the development
workspace; their source and binaries are not yet part of the published release.
Treat the configuration below as preparation for that rollout, not as a setting
supported by the current published server. The current transition establishes a
new security baseline; older clients and existing runtime data are not supported
through that cutover.

Application versions, HTTP API versions and signed-record versions are separate.
A new app release must not silently redefine an existing server contract. Keep
existing paths and response shapes for compatible clients; add optional fields,
or introduce a new major endpoint/proof version for an incompatible change.
Never rewrite signed records or silently replace a pinned server key.

## Release discovery

`GET /client/v1/policy` is public, bounded to 16 KiB and requires no account,
device identifier or credentials. It returns a `v: 1` document, platform release
rules, implemented API major versions and security protocol capabilities. It
does not authorize membership, replace key pins or supply arbitrary executable
download URLs. Clients ignore additional fields but reject an unknown schema.

The hosting configuration accepts an optional `client_policy` object. Omitting
it keeps required updates **off**. The versions below are illustrative, not the current published release:

```json
{
  "client_policy": {
    "v": 1,
    "platforms": {
      "ios": { "latest": { "version": "1.2.0", "build": 1200 }, "minimum": null },
      "android": { "latest": { "version": "1.2.0", "build": 1200 }, "minimum": null },
      "macos": { "latest": { "version": "1.2.0", "build": 1200 }, "minimum": null },
      "windows": { "latest": { "version": "1.2.0", "build": 0 }, "minimum": null },
      "linux": { "latest": { "version": "1.2.0", "build": 0 }, "minimum": null }
    }
  }
}
```

Merge this field into the private hosting configuration; do not replace the
other settings. Restart the hosting process after changing it. `latest` is a
published, installable release, not a build waiting for review. To require it,
set that platform's `minimum` to the release and set `enforce_after` to an
explicit activation time in Unix seconds. The host rejects a minimum greater
than `latest`. Versions compare numerically, followed by the build number.
For Windows/Linux use build 0 and increment the semantic version for a release.
Reset `minimum` to null to roll back a requirement without deleting app data.

The native client opens local profiles and chats immediately. Release discovery
runs independently in the background, at most once every five minutes, including
when returning to the foreground. Requests have a three-second timeout and no
redirects; there is no per-message version request. A cached policy is loaded
before native background work begins, and scheduled activation is reevaluated
locally. An absent endpoint or outage does not invent a requirement. A confirmed
requirement survives restart and outages until an eligible app is installed or a
valid replacement policy rolls it back.

When an update is required, a compact orange banner below the screen header reads
**Update required to go online.** It is centered, stays on one line, and has no
button or dismiss action. Users update through their store or the published
desktop release. Local history, search, profile unlock, Space selection, private
preferences and local backups remain available. Native entry points reject new
server work and shared edits, including sending/queuing messages, attachments,
synchronization, device linking and new calls. Background sync and call discovery
pause. Already admitted operations can finish; an existing call can continue and
end normally. The policy check itself remains available while restricted.

This client restriction is **not a server security boundary**. Authorization,
device revocation and replay protection remain server enforced regardless of a
claimed client version. The app neither installs updates silently nor uses a
store in-app-update SDK. Older releases cannot acquire this mechanism without an
app update.

## Current security baseline: clean cutover

This transition does not include a compatibility bridge or migration of existing
profiles, Spaces, notification routes or stored objects. Prepare matching app and
server builds, verify them together on fresh test data, and switch the services
as a coordinated release. Retire old clients rather than accepting their old
proof formats. Existing runtime data can be reset as part of the operator's
explicitly scheduled cutover; an app update itself must not silently erase the
local profile.

Prepare the new clients before resetting the services. Recreate test/reviewer
accounts and invitations against the new baseline, and replace their access
instructions when switching it on. Preserve signing credentials, service secrets
and original cryptographic test fixtures: none of these are obsolete runtime
data. A reset does not replace authorization, replay-protection or device tests.

Older installed apps without the update gate cannot display a new update notice
remotely. They must be replaced by the new app. Minimum-version policy governs
subsequent releases that already contain that mechanism.

## Later compatible releases

1. Deploy an additive discovery endpoint with all minimums disabled.
2. Publish and verify clients containing the update gate. Keep the previous
   server behavior available during this adoption period.
3. Confirm the target update is available in every enabled country and on every
   supported OS for that platform. Check normal store accounts, not just testers.
4. Announce the minimum, allow an appropriate grace period, then activate it.
   Never set an iOS minimum based on a release still Waiting for Review.
5. Retire an old protocol only after the replacement has shipped. Test both the
   retained client/server pair and the replacement pair, including offline start,
   denied membership, replay, attachments, calls and account deletion.

Backward compatibility does not mean accepting revoked devices, unverifiable
proofs or downgrading crypto after a failed request. A security retirement may
require an app update rather than preserving a vulnerable protocol indefinitely.

## Current implementation boundary

The release policy and its local-access restriction are new source changes, not a capability
of the existing 1.0.0 store builds. The security work changes mailbox request
proofs to v2, retention authorization, linked-device keys, compact authority checkpoints and iOS VoIP registration. The call-service fence now persists a root-recovery generation in its `recovery` column; the clean cutover requires a fresh call-service database rather than an in-place old-schema start.
Those changes are **not compatible with the previous installed clients** merely
because several resource URLs still contain `/v1`. Discovery exposes their
separate security capabilities. This incompatibility is deliberate for the clean
cutover above; support for those previous clients is outside its scope, rather
than an unfinished release requirement. Native signing, physical-device tests
and coordinated deployment remain necessary.

The baseline advertises `security.space_creation_work: 1`. The JSON body for
`POST /spaces/v1/create` includes a required unsigned 64-bit `work` nonce beside
`record` and `credential`. SHA-256 of the concatenation of
`elo.space.create.work.v1\0`, SHA-256(record UTF-8), SHA-256(credential UTF-8),
and the nonce as eight big-endian bytes must begin with 20 zero bits. The proof
is bound to the signed request and its credential. Verification precedes
provisioning; identity/network/deployment quotas still apply. It does not add a
challenge round trip and is never required for sending a message. A later change
to this work contract requires its own advertised version and coordinated
client support; changing the difficulty silently is not compatible.

For future releases, retain a versioned contract test fixture from each supported
client release. Tests of a new client against its own new server do not prove
backward compatibility. After establishing this baseline, keep data/schema
changes reversible until the rollback window closes; the present clean cutover
is not an automatic reset policy for future upgrades.
