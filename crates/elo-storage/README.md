# Independent attachment storage broker

Deploy this service with matching clients that support witnessed General and
external attachment descriptors. Validate the witnessed authorization flow,
provider access and object lifecycle on the intended deployment before offering
attachments to users.

`elo-storage` receives requests directly from the client over its separately pinned HTTPS endpoint. The Space API never receives the provider configuration, transfer bearer tokens, or provider credentials. Deploy it as a separate service account on the witness host; do not put its key or database on the API host. Deployment is a separate operational step.

The shared wire types and signing helpers live in `elo_core::attachments::broker`. `POST /storage/v1/command` carries an ELO1 device-signed command and the full owner-managed General `CallAuthorityProof`. Membership and configuration changes are verified from the content-addressed genesis; General must match its genesis nonce. Owner devices can configure or disable storage. Current readable members may request downloads; posting members may reserve and complete uploads. Cancellation of an unfinished upload requires the original uploader device or a current owner device; completed objects remain immutable until expiry.

**Independent freshness:** production requests require version 4 General proofs
bound to the operator-configured witness pin. Before authorizing a command or
consuming either an upload or download token, the broker obtains a signed,
nonce-bound current head from `POST <witness.url>/head`. It must exactly match the
proof or grant head. The broker persists the highest global journal position and
rejects lower positions or conflicting record IDs at the same position after a
restart. A changed operator pin requires an explicit floor migration; the server
never adopts a pin supplied by a client or falls back to legacy authority.

The in-memory witness lease lasts at most 30 seconds from the start of its
request, and never past its signed expiry. A cache hit does not renew it. A long
provider probe requires another valid lease before configuration is committed.
Expired leases, witness failures, nonce replay, oversized responses and redirects
fail closed. Thus revocation becomes effective within this bounded lease, rather
than immediately. A transfer admitted before revocation may finish within its
existing provider/stream timeout: upload provider calls are limited to 90 seconds;
download preparation and subsequent streaming are each limited to 90 seconds.
Already delivered ciphertext cannot be recalled. Account/device revocation must
be represented in the witnessed General authority to affect this gate.

**Deployment boundary:** keep the service listener on loopback and expose only
the documented storage routes through its independent HTTPS proxy. Configure
the client endpoint explicitly or through an approved hosting profile.
Retention is an owner-signed broker policy, enforced independently of the upload
client's clock or preferences.

## Configuration and credentials

The executable accepts `--config /etc/elo/storage/config.json`. The private JSON file contains:

```json
{
  "bind": "127.0.0.1:8791",
  "public_url": "https://storage.example.test/storage/v1",
  "data": "/var/lib/elo-storage",
  "secret_key": "/etc/elo/storage/secret.key",
  "max_spaces": 128,
  "trusted_loopback_proxy": true,
  "witness": {
    "url": "https://witness.example.test/witness/v1",
    "public_key": "<operator-verified Ed25519 public key, 64 lowercase hex characters>",
    "key_generation": 1
  }
}
```

The `witness` object is mandatory. Copy the independently verified deployment pin;
its HTTPS URL and public key must match the Space genesis. The witness HTTP client
disables proxies and redirects, limits responses to 16 KiB, and has a total
five-second request deadline. Missing or invalid pins prevent service startup.

The raw secret key is exactly 32 random bytes, stored in a separate `0600` regular file outside the database directory. The data directory must be private (`0700`). Provider configurations use XChaCha20-Poly1305 with a fresh nonce and authenticated Space/version context. Signed configure requests and plaintext provider credentials are not persisted. Views contain only the provider name, enabled state, revision, usage, and limits.

Only enable `trusted_loopback_proxy` behind a loopback reverse proxy that **overwrites** `X-Real-IP` with the actual peer address. The service requires a valid single IP in this header when this option is enabled. It never interprets `X-Forwarded-For`. With the option disabled, all reverse-proxied clients share the loopback peer's rate limits. Disable proxy request-body logging and Authorization-header logging. Proxy request buffering must be disabled for transfer routes.

First configuration is automatic: the owner proves the complete General chain and a 20-bit command-bound proof of work. No API-issued grant or manual Space allowlist is needed. Admission is bounded to 128 Spaces, four registrations per source IP per day, and 32 registrations globally per day. Four requests can be verified concurrently, one provider configuration can be probed concurrently, and eight transfer/cleanup operations can run concurrently. Additional source-IP and per-device request limits apply.

S3 credentials must be limited to the intended bucket and object prefix (`spaces/<space-id>/`). Endpoint URLs must use HTTPS, have no credentials/query/fragment/path prefix, and resolve exclusively to permitted public IP addresses. DNS results are pinned for each adapter lifetime and revalidated on the next operation. Proxies and redirects are disabled. An isolated RustFS S3 test verifies SigV4 rejection and the object lifecycle; external IAM policies and each production provider still require provider-specific validation.

MEGA accepts only a writable public folder link and its write authorization. It does not accept an account email or password. The fixed helper and MEGAcmd runtime are described in the deployment files. Runtime session credentials must remain on private volatile storage; provider operation output is not logged. Live MEGA folder interoperability requires validation against a real limited folder.

Owners configure storage during Space creation or later in Space settings.
Attachments start disabled. Compromise of the broker host can disclose its
provider credentials and delete ciphertext within their scope; filesystem
encryption does not protect credentials from an attacker controlling that host.
Use a dedicated folder/bucket and the smallest permissions available.

For Linux deployment, install `deploy/storage/mega_folder.py` as root-owned
`/opt/elo/storage/mega_folder.py`, alongside Python 3 and MEGAcmd. Use the separate
service account and limits in `deploy/storage/elo-storage.service`. Its config
path is `/etc/elo/storage/config.json`. Each MEGA operation runs in a private HOME
under `/run/elo-storage/mega` on tmpfs, with credentials supplied through a pipe
and fixed commands over a private Unix socket. No public WebDAV listener or
account login is used. Deadlines, core-dump prevention, bounded input/output,
parent-death handling and stale-operation cleanup limit discarded sessions.
Memory, swap and process limits also apply to all child processes. Keep backups
and their decryption keys independent of the attachment provider.

The client endpoint comes from explicit native build configuration (`ELO_STORAGE_URL` or
`TAURI_ELO_STORAGE_URL`) for the public hosting, or from an imported, approved
signed hosting profile for a private hosting. Each Space retains its own binding;
the endpoint is never inferred from an untrusted Space API response. Missing
configuration leaves this feature off. Updated recipients are required for the
new `external_storage` attachment descriptor: older strict parsers reject it.

### Operator-managed storage

An operator may add `"managed_storage": "/etc/elo/storage/managed.json"` to the
service configuration. This optional private file contains a validated
`provider` configuration and an explicit `allowed_owners` array of profile
identity IDs. Keep the file readable only by the broker service account; an
empty allowlist permits no owner to activate operator-managed storage.

The public hosting profile advertises only the provider type and attachment
retention, never the provider credentials. During Space creation the client sends
an owner-signed `ConfigureManaged` command, including the expected configuration
revision, proof of work for initial registration, and current witnessed General
authority. The broker checks the owner allowlist, probes the provider, and uses
the same configuration, replay, revision and encrypted-credential protections as
an owner-supplied provider. Credentials stay on the broker host.

The allowlist controls activation and reconfiguration. Removing an owner from it
does not revoke storage already configured for that owner's Spaces. Disable
storage through a separately authorized Space operation when revocation is
required. Existing objects retain their original expiry and provider generation.
See [the container installer](../../deploy/containers/README.md) for an isolated
API/witness installation with optional operator-managed S3 storage.

## Object lifecycle

Configuration, retention-policy, and disable requests require `expected_revision`. Every operation verifies its signed audience, Space, General stream, device, configuration head, nonce, and expiry. Configure requests live for at most 180 seconds; other commands live for at most 60 seconds. Replays of the exact accepted command reproduce its response; nonce reuse with different bytes fails. Transfer bearer tokens are derived using a separate HMAC domain and are stored only as SHA-256 hashes.

Reserve binds the immutable object ID, encrypted size, and ciphertext hash to the current provider version. The broker calculates and persists the absolute expiry from its own clock and the owner's signed policy; the client puts that returned expiry in the encrypted attachment descriptor and requires the same expiry on download. The broker streams ciphertext and checks exact byte length and SHA-256 before marking an upload successful. Upload completion is a separate signed operation; incomplete objects cannot be downloaded. Download and upload tokens are single-use, scoped to the object, action, and accepted General head, and expire within 120 seconds. Tokens are carried in the Authorization header, never in URLs.

The existing 5 MiB file limit and 50,000,000-byte Space quota remain enforced. Owners choose the existing 1/12/24-hour retention policy; new configurations default to one hour. Configure and Policy commands carry the owner's signature, and members cannot change the policy. A retention change affects new reservations only; existing objects retain their original expiry and provider generation. Migrated staging configurations without a signed retention policy reject new reservations until the owner sets one. Pending and failed objects count toward quota until cleanup succeeds. Disable stops future uploads and preserves existing downloads until each object's expiry. Changing provider creates a new encrypted credential generation; existing objects continue to use their original generation. Older credentials are removed only after no retained object needs them.

Cleanup deletes only an expired object or an object authorized for cancellation/failed-upload cleanup. Provider failure does not remove the broker's object record or release quota. A persisted 100-second upload lease prevents cleanup racing an interrupted provider write; interrupted uploads are cleaned after restart. No provider-wide or Space-wide recursive deletion is called.

## Validation

The crate includes durable-fence, CAS/replay, encrypted-secret, transfer-token, quota, expiry, adapter-isolation, and direct HTTP ciphertext round-trip tests. The local filesystem adapter is an injected test adapter; it is not a remotely selectable provider. Witness tests cover removed-member requests and existing transfer grants after lease expiry, durable rollback/fork floors, missing pins, and failed witness responses. The production proof path has no legacy fallback.

Run `python3 crates/elo-storage/tests/run_live_s3.py` on Linux x86_64 for the ignored real S3 integration test. The supervisor downloads the pinned official RustFS release, verifies its published SHA-256, creates an ephemeral private CA and credentials, and binds only to loopback. The test checks real PUT/GET/hash/delete, rejects a wrong SigV4 signature, rotates two buckets with CAS, and verifies immutable retention deadlines. It deletes both test buckets; the supervisor terminates its process groups and removes the temporary data and secrets. This passed against RustFS 1.0.0-rc.6. The test-only loopback/TLS adapter does not relax production endpoint rules. Live MEGA interoperability and a deployment security review remain separate checks.
