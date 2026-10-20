# elo.now scanner guidance

Read [the canonical threat model](../THREAT_MODEL.md) and
[security reporting policy](../SECURITY.md) first. They describe the actual
trust boundaries and known limitations; this file adds scanner setup and scope.

elo.now is an AGPL-3.0-only communication platform with Rust services and a
Tauri/React client. Security-sensitive paths include Space membership,
device authorization, encrypted message handling, invitation and hosting imports,
attachment storage, history retrieval and call admission.

## Build and offline tests

The image retains the public checkout at `/src`, Rust 1.98.1, Node 24, Python,
Linux WebKit dependencies, Cargo's Linux dependency cache and installed npm
dependencies. Debug symbols and frame pointers are enabled. Development
binaries and test executables are under `/src/target/debug`; frontend output is
under `/src/apps/desktop/dist`.

Run `sh .oss-scanner/check.sh` in `/src`. This runs the core/server suites,
the witnessed-Space example tests, the headless native-client suites used by CI,
frontend build/tests and Python protocol/deployment tests. Loopback sockets are
needed by some tests; external networking and real service credentials are not.
Existing ignored tests remain ignored and must not be counted as passing.

The image builds the Linux desktop client and server binaries. It does not
provide a graphical desktop, Apple SDKs, Android SDK/NDK, mobile devices or
external push/storage/media accounts. Swift/Kotlin and platform-specific Rust
sources are available for inspection, but native iOS/macOS/Android behavior
cannot be validated by this Linux image. Containers/lifecycle Python tests do
not replace the separate multi-container integration job.

## Priorities and untrusted input

- `crates/elo-core`: record/envelope parsing, signatures, device credentials,
  invitation and hosting import, recipient selection, authorization transitions,
  vault handling, history import/retrieval, expiry and replica synchronization.
- `crates/elo-team` and `crates/elo-witness`: public HTTP input, allocation and
  membership authorization, freshness/replay protections, witness journal
  consistency, restart/rollback boundaries and resource limits.
- `crates/elo-storage`: attachment authorization, provider configuration,
  credential isolation, URL/path handling and bounded uploads/downloads.
- `crates/elo-wake` and `crates/elo-call-service`: push routing, registration,
  call-only delegation, call admission, lifecycle races, WebSockets and queues.
- `apps/desktop/src-tauri`, `crates/tauri-plugin-elo-push`,
  `crates/tauri-plugin-elo-privacy` and `apps/desktop/src`: native commands,
  deep links/QR, rendered messages, attachments, local file boundaries,
  notification/call actions and locked-profile behavior.
- `deploy/hosting`, `deploy/storage`, `deploy/admin`, `deploy/diagnostics` and
  `deploy/containers`: admin authentication, credential handling, reverse-proxy
  trust, filesystem boundaries, diagnostics ingestion and deployment defaults.

Consider unauthenticated remote clients, malicious members with ordinary
permissions, revoked members/devices, replayed signed data, malicious hosted
replicas and hostile remote content. Do not assume a valid signature alone
proves current authorization or that an app's unlocked state permits all actions.
Look for cross-Space/cross-profile access and denial of service that exceeds
the documented resource budgets or blocks revocation/recovery.

## Interpreting findings

Use the canonical threat model when distinguishing a bug from an acknowledged
design limitation. In particular, age with long-lived keys does not provide a
ratchet, forward secrecy or post-compromise security; an authorized recipient
can retain plaintext; metadata is not hidden; the witness does not cover every
private-chat operation; and a hostile host can deny service. These are not
claims that mitigations against specific attacks are unnecessary.

Report a concrete boundary violation with attacker prerequisites, affected
versions/paths, a local reproducer, observed impact and a regression test where
practical. Rate unauthenticated remote code execution, secret extraction and
cross-user decryption/access as high or critical according to demonstrated
impact. Assess denial of service by attacker cost, persistence, recovery and
scope, rather than treating every rejected request or finite quota as a defect.
Report bypasses of a documented mitigation even when the broader threat has
known limitations.

Scan this project's code and modifications. For vendored code, distinguish an
elo-specific change from an upstream dependency issue. Do not contact deployed
elo.now services, use real accounts, send notifications or access user data.
Use synthetic identities, local services and temporary storage for reproducers.
