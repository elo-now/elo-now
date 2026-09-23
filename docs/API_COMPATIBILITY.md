# API compatibility and application updates

**Status: next-release work, not a feature of release 1.0.0.** The policy endpoint
and client gate described here have been implemented and tested in the development
workspace; their source and binaries are not yet part of the published release.
Treat the configuration below as preparation for that rollout, not as a setting
supported by the current published server. The security transition still has the
compatibility limits listed at the end of this document.

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
it keeps required updates **off**. Example:

```json
{
  "client_policy": {
    "v": 1,
    "platforms": {
      "ios": { "latest": { "version": "1.0.0", "build": 1082 }, "minimum": null },
      "android": { "latest": { "version": "1.0.0", "build": 1082 }, "minimum": null },
      "macos": { "latest": { "version": "1.0.0", "build": 1082 }, "minimum": null },
      "windows": { "latest": { "version": "1.0.0", "build": 0 }, "minimum": null },
      "linux": { "latest": { "version": "1.0.0", "build": 0 }, "minimum": null }
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

The new native client checks this endpoint once before opening a profile. The
request has a three-second timeout, no redirects and no per-message polling.
An absent endpoint or outage does not invent a requirement; a previously
confirmed requirement is retained locally until a valid replacement policy is
received. The app shows an Update required screen with Get update and Check
again. It does not end an already running call or install software silently.
The destination is compiled into the app: Apple App Store, Google Play or the
publisher's latest GitHub desktop release. Mac App Store builds must set
`ELO_DISTRIBUTION_CHANNEL=mac-app-store`; ordinary Mac builds use GitHub.

This is an app startup gate, **not a security boundary**. Authorization, device
revocation and replay protection remain server enforced regardless of a claimed
client version. Google Play's optional in-app-update SDK is not integrated; the
button opens the app listing. Older installed releases do not contain this gate
and cannot acquire it without an app update.

## Safe rollout

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

The release policy and its startup gate are new source changes, not a capability
of the existing 1.0.0 store builds. The security work changes mailbox request
proofs to v2, retention authorization, linked-device keys and iOS VoIP registration.
Those changes are **not compatible with the previous installed clients** merely
because several resource URLs still contain `/v1`. Discovery exposes their
separate security capabilities. Do not deploy this security server build over
the current services while old clients are still expected to work. A complete
compatibility bridge for that transition is not implemented yet.

For future releases, retain a versioned contract test fixture from each supported
client release. Tests of a new client against its own new server do not prove
backward compatibility. Keep data/schema changes reversible until the rollback
window closes; do not reset existing Spaces as an upgrade strategy.
