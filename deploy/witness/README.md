# Authorization witness deployment

The repository implements witnessed General in the native client, hosting API and this service. Deploy matching versions with explicitly provisioned trust pins; installing or activating the witness alone does not configure the other components. This guide is a deployment contract, not evidence that any particular installation has passed acceptance checks. No automatic activation, signing key, live deployment address, or provider credentials are included.

The witness serializes version 4 General membership changes. Registered owner-signed invitation policies can admit a device while the owner is offline. Admission still requires the invitation key, the candidate device signature over the same intent bytes, a fresh witness challenge, and the candidate's signed contact. Approval-required invitations and readmission require explicit owner approval. An ordinary invitation grants Read and Post only. The service cannot replace an owner proposal with its own unrestricted membership change: clients also verify the embedded owner or admission evidence. It is not an independent controller for ordinary private chats. See the [authority-version overview](../../PROTOCOL.md#authority-versions-and-hosted-general) and [threat model](../../THREAT_MODEL.md#hosted-general-trust-boundary).

## Trust and deployment boundaries

Deploy under a dedicated `elo-witness` system account on a host separate from the API/hosting service. The API must not receive the witness signing key or write access to the witness state, configuration, or runtime directory. Separate Unix users on the same machine do not protect against compromise of that machine's root account.

Two VPS instances at OVH still share a provider and may share account administration, snapshots, and recovery credentials. That remains a common compromise and availability risk. This deployment does not claim automatic protection against restoring an entire witness snapshot, compromise of the witness host or signing key, or compromise of the shared provider account.

The client trusts an explicitly provisioned HTTPS URL, Ed25519 public key, and key generation. Native builds use `ELO_WITNESS_URL`, `ELO_WITNESS_PUBLIC_KEY`, and `ELO_WITNESS_KEY_GENERATION` together; `TAURI_` aliases support mobile build forwarding. Neither hosting responses nor invitation descriptors can provision that trust anchor. Existing pinned Spaces do not automatically adopt a different key or generation.

## Files and permissions

Install the reviewed `elo-witness` binary at `/opt/elo/bin/elo-witness`, owned by root and not writable by the service account. Install [elo-witness.service](elo-witness.service) as a system unit. The unit uses a loopback listener behind an HTTPS reverse proxy and restricts network access to localhost.

Create the system account and `/etc/elo/witness` before starting the unit. Use the following ownership and permissions:

| Location | Owner | Mode | Purpose |
| --- | --- | --- | --- |
| `/etc/elo/witness` | `elo-witness:elo-witness` | `0700` | Read-only service configuration under the unit's filesystem sandbox |
| `/etc/elo/witness/config.json` | `elo-witness:elo-witness` | `0600` | Reviewed configuration copied from the example |
| `/etc/elo/witness/signing-key.bin` | `elo-witness:elo-witness` | `0600` | Exactly 32 raw bytes of an independently generated Ed25519 signing seed |
| `/var/lib/elo-witness` | `elo-witness:elo-witness` | `0700` | SQLite database, WAL, and process lock; created by `StateDirectory` |
| `/run/elo-witness` | `elo-witness:elo-witness` | `0700` | Per-process startup and activation files; created by `RuntimeDirectory` |

The signing seed is neither hexadecimal text nor a PEM file. Provision it using a trusted key-generation workflow and place its matching 64-character lowercase public key in the configuration. Keep the key outside the SQLite/data directory and its routine snapshot. Protect any separate key backup. Never include the key in source packages, logs, tickets, or public configuration examples.

`prepare.py` provisions the witness and attachment broker together on their independent host. Run it as root with Python 3 and OpenSSL available:

```sh
python3 deploy/witness/prepare.py --public-origin https://witness.example.invalid
```

Replace the example origin with the reviewed deployment origin. The script creates separate `elo-witness` and `elo-storage` nologin accounts, private key/configuration/state/runtime directories, and 32-byte keys generated on that host. It sets loopback listeners at ports 17845 and 17846. Existing keys are preserved; conflicting ownership, modes, linked files, or configuration fail closed instead of being repaired or overwritten. Output contains only the public witness pin and permission metadata. The script does not install or start units, create startup/activation documents, configure a proxy, or use provider credentials. Store and independently provision only the public pin on clients. File-safety regressions run with `python3 -m unittest discover -s deploy/witness -p test_prepare.py`.

Replace the deliberately invalid placeholders in [config.example.json](config.example.json). Use absolute paths without symlinks. The HTTPS pin must end in `/witness/v1`; the listener must remain on loopback. The data directory must not contain the signing key, startup file, or activation file. Do not expose the runtime directory through the proxy.

Expose only `/witness/v1/command` and `/witness/v1/head` through the HTTPS proxy. Keep `/livez` and `/readyz` local. With `trusted_loopback_proxy: true`, the proxy must **overwrite** `X-Real-IP` with the actual client's IP address; it must not preserve a client-supplied header. The service rejects forwarded requests without a valid address. Bound request size to the service's 9 MiB request limit and set finite proxy request timeouts. Run one witness process against a database; the exclusive process lock prevents a second cooperating writer.

The unit's memory and task limits are initial operating limits, not load-test results. An unexpected process restart will require a new operator activation.

## Sealed startup and operator activation

Every process starts sealed. It writes `/run/elo-witness/startup.json` with a fresh `startup_nonce`, its observed journal position, public key, and key generation. `/livez` reports process liveness; `/readyz` stays unavailable while sealed. Mutations and signed freshness replies are denied. Stale activation files from a previous process are removed.

Activation requires the exact latest journal position retained **outside the witness host and its snapshot/recovery boundary**. That position is the sequence and signed receipt record ID for the whole witness journal, covering all acknowledged changes across Spaces. A receipt from one client or an older offline copy is insufficient unless you can establish that no later change was acknowledged. Verify retained receipt signatures against the independently provisioned witness key. Independent receipt collection and the operator's activation workflow are not automated by this service.

1. Read the new startup nonce and compare the observed position with that independently retained position. Treat `observed_position` as an untrusted observation, not recovery evidence.
2. If the positions differ, or the independent evidence is unavailable, leave the service sealed. Recover and reconcile verified state first. Do not lower the expected position, delete journal rows, reset policy counters, or erase tombstones to make activation succeed.
3. Prepare a private activation document with the following schema. Supply `expected_position` from the independent evidence. Set `expires_at_ms` to a current Unix timestamp in milliseconds, no more than ten minutes ahead.

```json
{
  "startup_nonce": "NONCE_FROM_THIS_PROCESS_STARTUP_FILE",
  "expected_position": {
    "sequence": 123,
    "record_id": "RECORD_ID_FROM_INDEPENDENTLY_RETAINED_SIGNED_RECEIPT"
  },
  "public_key": "INDEPENDENTLY_PROVISIONED_WITNESS_PUBLIC_KEY",
  "key_generation": 1,
  "expires_at_ms": 0
}
```

The sample is deliberately not activatable. For a verified, never-used empty journal only, the expected position is `{"sequence":0,"record_id":null}`. An empty database restored over a previously used deployment is not a new journal.

4. Install the reviewed document with mode `0600`, owned by `elo-witness`, to a temporary file within `/run/elo-witness`, then atomically rename it to `activation.json`. A local readiness request consumes it once. A rejected or stale document must be reviewed and recreated; it is not a retry token for another process.
5. Confirm local `/readyz` readiness and retain subsequent acknowledged signed receipts independently. Keep the runtime activation file out of backups.

**Never copy `observed_position` automatically into `expected_position`.** Do not add activation generation to `ExecStartPre`, restart hooks, health checks, backup restore scripts, or a scheduled task. Doing so would remove the independent check that makes a restored snapshot fail closed.

## Integrity, clocks, and recovery

Each mutation and its signed receipt commit in one SQLite transaction. The receipt includes a digest of that Space's stored authority proof, invitation policies and counters, challenges and consumption state, and removal tombstones. Startup and activation verify the materialized state against the latest signed receipts; each request verifies the relevant Space before issuing a new signature. Restoring only an older membership or policy table while keeping newer receipts is rejected.

This digest detects inconsistent partial restores. A consistent full restore contains old state and old valid signatures, so the independent high-water evidence remains necessary. Back up SQLite consistently, including its committed WAL state; copying only a live `witness.sqlite` file is not a reliable snapshot. Preserve the complete journal and authority-bearing tables together.

A backwards clock or divergence from the process's fixed monotonic clock anchor seals the process. A process with a clock failure cannot be reactivated; correct the clock, restart, and repeat independent verification. Client freshness is nonce-bound and limited to 30 seconds from the start of the request. Clients persist their highest observed witness position, but restoring an old client profile is not an independent witness rollback anchor.

Key rotation and unsealing after lost independent evidence require a separately designed recovery procedure. This template intentionally supplies neither an automatic reset nor a fallback to hosting-authorized freshness.
