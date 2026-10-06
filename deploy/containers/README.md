# Two-host Linux container deployment

This package builds the current source into local images for a **new, empty
installation**. It is not a migration tool or a published elo image registry.
Use matching clients that support imported hosting profiles and witnessed
General. Older released clients do not acquire these capabilities by changing
an API URL.

| Host | Services | Persistent state |
| --- | --- | --- |
| API | `elo-team host`, Caddy | Hosted Spaces, ciphertext replicas, service keys, TLS state |
| Independent witness | `elo-witness`, Caddy, optional `elo-storage` | Authorization journal, witness key, optional broker database/key, TLS state |

The optional broker supports S3-compatible providers with the existing owner
configuration flow. It has no provider credentials by default. MEGAcmd is not
included in these images; do not advertise MEGA support from this package.
Calls, TURN, LiveKit and mobile push are not included. The hosting profile has
no push endpoint. Message retention and attachment retention remain separate:
this initializer offers 24 hours, 48 hours and no automatic message expiry;
the broker still uses its own supported attachment policy.

## Prerequisites and trust boundaries

Use two separate Linux machines, current Docker Engine and Compose, Python
3.11 or newer, OpenSSL with Ed25519 support, public DNS names, correct clocks
and working HTTPS egress. This is a rootful Linux Docker layout, not a Docker
Desktop, rootless Docker, Swarm or Kubernetes recipe. Reserve numeric UIDs
21001–21005 for this installation; they must not belong to unrelated host
users or services. Containers do not require matching host login accounts.

Allow inbound TCP 80/443 for Caddy's automatic TLS and managed SSH access.
Do not expose 18900/18901, 17845 or 17846. The Rust services deliberately bind
only to loopback and trust `X-Real-IP` only from a loopback peer. All containers
therefore use Linux host networking, and Caddy overwrites this header. There
are no Docker port mappings. Port 18901 is a private API operator listener and
is never proxied. Witness readiness/liveness and broker health are also not
public proxy routes. Do not run an additional untrusted loopback proxy or
untrusted containers on these machines: host networking is not network
isolation. Run only one instance of each service against its data directory.

Keep the witness independent of API administration and backups. Two machines
under the same compromised provider account are not independent protection
from that provider. Docker administrators and root can read mounted secrets.
Container hardening does not change that boundary. SELinux hosts require a
reviewed policy for these private bind paths; this package does not disable
SELinux or silently relabel system directories.

## Build reviewed source

On each target architecture, from the reviewed source checkout:

```sh
VERSION=1.0.5-source-YOUR_REVIEWED_REVISION
sh deploy/containers/build.sh "$VERSION" api
# On the independent witness host:
sh deploy/containers/build.sh "$VERSION" witness
```

`build.sh` creates and removes a temporary allowlisted context. It includes
only the four Rust server crates, required protocol data and SQL migrations,
plus the container runtime helpers. It does not send the repository, desktop
application, `.private`, internal documentation, credentials or runtime data
to Docker. Do not replace this with `docker build .` at the repository root.

The multi-stage build uses Rust 1.98.1 and local `elo-api:VERSION`,
`elo-witness:VERSION`, `elo-storage:VERSION` tags. Cargo removes client-only
feature edges from the workspace lock. A verification step rejects any new
package version, source or checksum, then the build uses `--locked`. The
resulting lock is retained at `/usr/share/doc/elo/Cargo.lock` in each image.
No image is pushed, and Compose refuses to pull a missing elo image. Building
requires network downloads and space for Rust dependencies and build output.
Compilation defaults to two parallel Cargo jobs; `CARGO_BUILD_JOBS` can override
this explicit build limit on a suitably provisioned build machine.

Default base tags (`rust:1.98.1-trixie`, `debian:13-slim` and
`caddy:2.11.7-alpine`) are versioned but tags and distribution packages can
change. For repeatable production releases, record and use reviewed image
digests through `RUST_IMAGE` and `RUNTIME_IMAGE`, pin Caddy by digest in the
Compose file, retain the built images and record their image IDs. This is a
locked-source recipe, not a claim of byte-identical images across time.
Transfer built images with `docker save`/`docker load` if the destination
should not compile them. Do not transfer state or keys together with images.

The runtime follows [Debian 13 stable](https://www.debian.org/releases/) and
the proxy uses the current stable
[Caddy 2.11.7 release](https://github.com/caddyserver/caddy/releases/tag/v2.11.7),
checked on 2026-10-06. The official
[Caddy image manifest](https://github.com/docker-library/official-images/blob/master/library/caddy)
lists its Alpine tag. Rust remains pinned to the repository toolchain rather
than silently selecting a different compiler; the official
[Rust image catalog](https://hub.docker.com/_/rust/) provides the 1.98.1 Trixie
variant. Updating the compiler requires the repository's corresponding checks.

## Initialize the witness host first

Keep state outside the checkout. The following commands prepare files only;
they do not start containers, configure provider credentials or unseal witness.

```sh
sudo python3 deploy/containers/init.py witness \
  --state /srv/elo-witness --origin https://witness.example.org \
  --version "$VERSION" --with-storage
sudo docker compose --env-file /srv/elo-witness/compose.env \
  -f deploy/containers/compose.witness.yaml config --quiet
sudo docker compose --env-file /srv/elo-witness/compose.env \
  -f deploy/containers/compose.witness.yaml pull proxy
sudo docker compose --env-file /srv/elo-witness/compose.env \
  -f deploy/containers/compose.witness.yaml up -d
```

Omit `--with-storage` to omit the broker and its public proxy routes. Keep
`--env-file` on every subsequent Compose command; it also selects the storage
profile. Read-only config mounts fail if their source path is missing instead
of creating an empty root-owned directory. Data/config directories have mode
0700, private files 0600, and each service has a distinct UID. Config and key
mounts are read-only; data mounts persist through container recreation. Runtime
and temporary directories use bounded tmpfs. Services run without root,
privileged mode, a Docker socket, or general Linux capabilities. Only Caddy
receives `NET_BIND_SERVICE` to bind HTTP/HTTPS.

Initialization is repeatable with identical arguments and never overwrites
keys or configuration. Changed arguments or unsafe ownership/permissions fail.
A missing service key beside existing data requires restoring the original
key; generating a replacement is not recovery. The initializer does not repair
permissions automatically or start a service with an incomplete configuration.

Securely transfer **only** `/srv/elo-witness/public/witness-pin.json` to the API
operator and independently verify its URL, public key and generation. Retain
another trusted copy outside both hosts. DNS names alone do not establish that
the pin belongs to the intended operator.

## Explicit witness activation

Every witness process starts sealed, including after Docker restart or host
reboot. Compose health uses `/livez`; a healthy container can still be sealed.
Read its current startup document locally:

```sh
sudo docker compose --env-file /srv/elo-witness/compose.env \
  -f deploy/containers/compose.witness.yaml exec -T witness \
  cat /run/elo-witness/startup.json
```

Obtain the exact latest acknowledged **global journal position** from a trusted
record kept outside the witness host and its snapshots. Verify the pin and
the supporting receipts using the [witness procedure](../witness/README.md).
The helper accepts the following bounded public anchor document:

```json
{
  "expected_position": {"sequence": 123, "record_id": "64_lowercase_hex_record_id"},
  "public_key": "independently_verified_64_lowercase_hex_public_key",
  "key_generation": 1
}
```

The helper compares this supplied position with local state; it cannot prove
that an operator's input was externally retained or is the latest position.
It does not authenticate arbitrary JSON as a trusted receipt. **Never fill
`expected_position` by copying `observed_position` from startup**, and never
run activation from a restart hook, health check, timer, cron or restore job.
A stale externally retained receipt also cannot prove that no later changes
were acknowledged. Maintain the independent anchor as part of operation.

For a verified **never-used** deployment only, the independent starting
position is `{"sequence":0,"record_id":null}`. Use that position with the
independently retained pin and add `--first-bootstrap` to the following command.
This confirmation is forbidden for a restored, reset or replaced journal, even
when its database appears empty. Later activations omit that flag.

```sh
# trusted-anchor.json was supplied and verified outside this host.
sudo docker compose --env-file /srv/elo-witness/compose.env \
  -f deploy/containers/compose.witness.yaml exec -T witness \
  python3 /opt/elo/activate.py --anchor-stdin < trusted-anchor.json
sudo docker compose --env-file /srv/elo-witness/compose.env \
  -f deploy/containers/compose.witness.yaml exec -T witness \
  curl --fail --silent http://127.0.0.1:17845/readyz
```

Activation binds the current startup nonce, pin, generation and supplied
position, expires after five minutes, and is written privately and atomically
into runtime tmpfs. The service remains responsible for final validation.
Neither initialization nor activation advances an external anchor. A mismatch
requires investigation or verified recovery, not choosing another position.

## Initialize API and export its public profile

On the API host, use the independently verified public witness pin. Set
`CREATOR_ID` to the intended user's existing identity ID from elo. Repeat
`--creator` for other identities permitted to create Spaces. With no creator
arguments the server denies all new Space creation; importing a hosting link
does not grant creation, owner or membership privileges.

```sh
CREATOR_ID=REPLACE_WITH_64_LOWERCASE_HEX_IDENTITY_ID
sudo python3 deploy/containers/init.py api \
  --state /srv/elo-api --origin https://api.example.org \
  --version "$VERSION" --witness-pin ./witness-pin.json \
  --name 'Private elo' --creator "$CREATOR_ID" \
  --storage-url https://witness.example.org/storage/v1
sudo python3 deploy/containers/export.py --state /srv/elo-api --version "$VERSION"
sudo docker compose --env-file /srv/elo-api/compose.env \
  -f deploy/containers/compose.api.yaml config --quiet
sudo docker compose --env-file /srv/elo-api/compose.env \
  -f deploy/containers/compose.api.yaml pull proxy
sudo docker compose --env-file /srv/elo-api/compose.env \
  -f deploy/containers/compose.api.yaml up -d
```

Omit `--storage-url` if the witness host has no broker. The independent backup
bearer key is 64 lowercase hexadecimal characters; witness, broker and hosting
profile signing keys are separate raw 32-byte keys. The profile signing key
lives under `export/config`, is never mounted into API, and is used only by an
offline one-shot container running as UID 21005. Its public output is under
`/srv/elo-api/public`: `hosting-profile.json`, `hosting-link.txt`, a locally
rendered `hosting-qr.svg`, and an HTML page displaying that QR plus a copy link
button. After export and API startup, Caddy serves the page directly at
`https://api.example.org/hosting/` and redirects `/hosting` there. The proxy
mounts only this public directory read-only; its file server does not mount
the export signing directory, service configuration or data. Share this HTTPS
address through a trusted channel. In elo Hosting, scan the QR or paste the
copied link into the import field; this page does not rely on an unsupported
browser-to-app hosting deep link. QR rendering is local and uses no external
QR service or CDN. If distributing the page separately, keep its HTML and SVG
beside each other.
Keep all other state directories private. The signature proves consistent
contents; clients still need the user's approval of the operator and pins.

The S3 broker remains disabled for each Space until its owner configures it.
Use a dedicated bucket/prefix and least-privilege HTTPS S3 credentials with the
existing [broker flow](../../crates/elo-storage/README.md). Credentials go
directly to the broker, not in this public hosting profile or the API config.
Provider object lifecycle, cleanup and quota need a real-provider acceptance
test before offering files to users.

For an operator-managed S3 option, prepare a root-owned mode-0600 file outside
the checkout on the witness host, using this shape with the operator's own
credentials and intended owner identities:

```json
{
  "provider": {
    "provider": "s3_compatible",
    "endpoint": "https://s3.example.org",
    "region": "REGION",
    "bucket": "DEDICATED_BUCKET",
    "access_key": "PRIVATE_ACCESS_KEY",
    "secret_key": "PRIVATE_SECRET_KEY"
  },
  "allowed_owners": ["64_lowercase_hex_identity_id"]
}
```

At initial witness provisioning add `--managed-s3 /root/elo-managed-s3.json`
together with `--with-storage`. The initializer installs the file privately
under the storage service's read-only config mount; neither API nor witness
receives it. Add `--advertise-managed-s3` at API initialization to include only
the public `{provider:"s3",retention_hours:1}` option in the signed hosting
profile. This advertisement does not enable a Space automatically: its
currently authorized owner must request managed configuration, and that owner
must also be in the broker's `allowed_owners` list. An empty list grants nobody
this option. Keep the API creator allowlist and broker owner allowlist aligned
with the intended users; they govern different operations. Do not copy the
private S3 JSON to the API host or distribute it with the hosting link.
The allowlist controls new managed-configuration requests. Removing an identity
from it does not disable storage already configured for a Space or delete its
retained provider generations; do not use that edit as a storage revocation
procedure. The broker's production S3 adapter requires a public HTTPS endpoint
and rejects private/loopback addresses; this package does not run a local S3
server in another container.

## Backups, upgrades and acceptance

For the smallest consistent backup, stop the role's containers and copy its
complete state tree with numeric owners and modes preserved. Back up keys and
encrypted databases as a coherent set, including SQLite WAL files if present;
do not copy live SQLite files individually. Encrypt off-host backups and keep
their recovery key separately. A broker database backup is not a backup of its
provider objects. Preserve still-needed ciphertext objects and provider
generations, and test their restoration. Do not back up runtime startup or
activation documents. Retain witness trust anchors independently from both
hosts and backup snapshots. The API and witness have separate backup sets;
no API backup job receives witness secrets.

For an upgrade, review compatibility, make and verify backups, build a new
immutable local version tag, then deliberately edit only `ELO_VERSION` in the
role's private `compose.env` and recreate its services. Do not rerun init with
different arguments to replace configuration. Any witness restart requires
new manual activation against the current trusted external anchor. Image
rollback does not roll back database schemas or prove safe state rollback;
test restoration before relying on it. Monitor sealed readiness separately
from process liveness, disk/quota, backup freshness, certificates, provider
cleanup failures and time synchronization. This package does not install an
alerting or external-anchor collector service.

Local checks without image downloads or a running Docker daemon:

```sh
python3 -B -m unittest discover -s deploy/containers -p 'test_*.py' -v
sh -n deploy/containers/build.sh deploy/containers/entrypoint.sh
```

CI additionally builds all three Linux images and runs `smoke.py` against
disposable synthetic state. That check covers non-root startup, sealed witness
activation, recreation with retained keys, offline public profile/QR export,
and the generated Caddy HTTP routes.
It does not contact a real storage provider or issue public TLS certificates.

The tests cover stable independent keys, retained data on reinitialization,
missing-key failure, permissions, links, invalid origins, manual activation,
source context boundaries and resolved Compose security settings. They do not
establish Linux image builds, TLS issuance, provider interoperability or a
two-host security acceptance result. Before using a deployment, verify those
on disposable Linux hosts: signed profile import; restricted creation; current
membership; message expiry; real S3 upload/download/expiry; restart with sealed
witness; retained data and keys after recreation; wrong/stale activation
rejection; and restore rejection against a newer independently retained anchor.

After all three images have been built locally, run the bounded Linux image
smoke check (a current Docker Engine with volume subpath support):

```sh
python3 -B deploy/containers/smoke.py --version "$VERSION"
# If the versioned proxy image is already present, also test its HTTP routes:
python3 -B deploy/containers/smoke.py --version "$VERSION" --caddy-image caddy:2.11.7-alpine
```

It pulls no images and uses uniquely named disposable volumes and an internal
network namespace. It verifies CLI execution, real Linux initializer ownership,
service health, sealed startup, rejection of an incorrect anchor, explicit
first-bootstrap activation, data-volume markers across container recreation and
offline signed-profile/QR export. With `--caddy-image`, it also serves the real
exported page and QR through the generated routes on isolated HTTP ports and
checks that the witness proxy hides private health routes. It removes only its
own containers, volumes and network in `finally`.
The test sends no Space or provider commands and is not public TLS or two-host
acceptance. It never mounts the Docker socket or existing application data.
