# Self-host elo.now on one VPS

This guide is for a **new, empty installation** on Debian 13 or Oracle Linux 10. It uses one VPS and one public application origin. It covers hosted Spaces and encrypted messages, attachments, chat audio/video sessions, and optional mobile notifications. There is no migration from the publisher's installation and no requirement for `api.elo.now`.

The configuration below is the baseline without an independent witness. For
witnessed General and a separate attachment broker, use the
[two-host container deployment](../deploy/containers/README.md), or follow the
native [witness deployment](../deploy/witness/README.md) and
[attachment broker instructions](../crates/elo-storage/README.md).
They require a host separate from the API, independently provisioned matching
pins in clients and services, and the documented activation and acceptance
checks. A single API-origin override does not enable either integration. The
single-VPS instructions below do not establish the witness trust boundary.

The examples use `chat.example.org` for the app API and media WebSocket, and `turn.example.org` for TURN on the same VPS. Replace both names throughout. Keep all private files and credentials **outside the source checkout**. Never put an SSH password, MEGA password, Firebase service account, APNs key, LiveKit secret or TURN secret in the mobile/desktop app.

Debian 13 is the deployment path exercised by this project. Oracle Linux 10 follows the same service layout, but still requires its own end-to-end acceptance run, especially package availability, SELinux policy and media ports. Do not present an untested OEL10 installation as verified.

For upgrades to an existing installation, read [API compatibility and application updates](API_COMPATIBILITY.md) first. The current security baseline is a clean cutover with matching clients and services, without older-client support or existing-data migration; this guide is not an in-place migration procedure. The optional `client_policy` field in `/etc/elo/host/config.json` controls platform minimums. Leave them disabled until the replacement app is available to users.

## Current-source container deployment on two hosts

The [container deployment package](../deploy/containers/README.md) provides a
separate path for new installations using current matching clients and
services: an API host and an independent witness host, with an optional
MEGA/S3 attachment broker on the witness host. Optional API-host services provide
mobile push and audio/video sessions through LiveKit and TURN. It builds local versioned
images from an allowlisted source context; no published elo image is assumed.
The initializer creates separate persistent data and private key directories,
restricts new Space creation to explicitly listed identities by default, and prepares a
signed public hosting profile for import. Linux host networking preserves the
services' loopback-only trust boundary behind a local TLS proxy.

The optional [hosting administration panel](../deploy/admin/README.md) edits
retention policies, creator allowlists and managed storage, then publishes a
signed import QR. It requires a configured WireGuard client and an HTTPS Basic
Auth password. The panel configures hosting; users create Spaces in the app.

Every witness process remains sealed until the operator explicitly activates
it against a separately trusted, latest journal anchor. The package does not
automate that trust decision, external anchor collection or automated backups. Local initializer and Compose
validation are distinct from a real Linux build, two-host deployment and
restore acceptance run. Follow the package's prerequisites, activation and
acceptance instructions before offering this path to users. The single-VPS
instructions below remain a separate deployment layout.

## 1. What runs where

### Imported hosting profiles

Current clients keep a device-local hosting catalog. **elo.now** is present on
first use. In **Create Space**, use **+** beside Hosting to scan or paste the
operator's `elo://hosting/v1#…` configuration, inspect the endpoint and policies,
and explicitly add it. Removing a catalog entry only hides that creation option;
it does not disconnect or migrate existing Spaces. The default entry can be
restored. The catalog is not synchronized between devices.

The signed profile contains a name, revision, creation endpoint, witness pin,
optional storage, push and call endpoints, allowed message policies
and a default policy.
The signing key identifies the profile. Import is an explicit trust decision:
a self-signature does not identify a trustworthy operator. Later imports must
preserve the approved endpoints and keys and increase the revision. Removed
entries retain their pins, so removing and re-adding is not a key-reset flow.
Each joined Space separately retains its hosting binding in encrypted profile
state. Host selection never reassigns an existing Space.

Each imported hosting may declare `push_url` as a canonical HTTPS origin ending
in `/` and `call_url` as an HTTPS endpoint ending in `/calls/v1`. Omit either
field, or set it to `null`, when the service is not provided. The client does
not fall back to public services for that private Space. Call controls are
available only when that hosting provides sessions. Native mobile push uses
separate registration credentials per approved endpoint while sharing the
installation's platform push token. Policies, route publication, read receipts
and account deletion stay scoped to their hosting; removing one registration
does not cancel another hosting's notifications. All declared endpoints are
pinned by the approved signed profile, including across updates.

The relay's Firebase credentials must belong to the Firebase project embedded
in the installed mobile app. An unrelated operator cannot use an arbitrary
Firebase project with the store binary. They need a matching app build or an
appropriately authorized delivery service; this package does not implement a
cross-project gateway. Never distribute the publisher's service-account key
with a hosting profile.

Private-host invitation links carry a compact hosting identifier in addition
to the invitation capability. Recipients must import that hosting's configuration
before opening its invitation; an invitation cannot supply or replace a trusted
witness key. The full invitation fragment remains on the client. The server
receives only the ciphertext locator and signed admission requests.

The server's `allowed_message_retentions` is authoritative. Omission retains the
public policies `[21600,43200,86400]` (6/12/24 hours). A private operator may use
`[86400,172800,"no_expiry"]`. No expiry keeps server delivery copies after
recipient acknowledgment, subject to quota and explicit deletion; it does not
disable message **Keep**, attachment expiry, access revocation or backup policy.
See [retention semantics](REPLICA_RETENTION.md). Client and server must both
support the selected policy.

`allowed_creators: null` permits public creation; `[]` denies creation; a list
of identity IDs permits those creators. Importing the public hosting QR grants
neither creation permission nor Space membership. Resource limits still apply.
Creation can be signed by a directly authorized or paired device of an allowed
identity. The host validates the same-identity credential chain and rejects
creation if that device or any delegation ancestor is revoked there. This does
not admit a paired device to existing Spaces or grant it their management rights.

Storage may be owner-configured or operator-managed. The public profile only
advertises the broker and provider type. For managed storage, the broker reads
a separate private `managed_storage` file containing `provider` and
`allowed_owners`; a signed request from a currently authorized owner is required
to activate it. The client submits that request during creation when the selected
hosting offers managed storage. Neither the API nor QR gets the credentials.
Provider changes use the existing storage revision and cleanup rules. The container package
includes S3 and an optional MEGAcmd image for limited MEGA folder credentials.

### Baseline native single-VPS layout

The following table and numbered setup steps describe the native systemd/Nginx
layout. Container deployments use the separate Compose services and state paths
in the [two-host package](../deploy/containers/README.md).

| Component | Install on the VPS | Public route / port | Private configuration |
| --- | --- | --- | --- |
| Nginx and TLS | Yes | `https://chat.example.org` on TCP 443 | TLS certificate and allowlisted proxy routes |
| `elo-team host` | Yes | Spaces, encrypted Replica, `/hosting/v1/realtime` WebSocket and attachment gateway behind Nginx | `/etc/elo/host/config.json` |
| Attachment storage | Choose local, MEGA WebDAV or S3-compatible | No direct public storage endpoint | `attachment_storage` in the host config |
| `elo-call-service` | For calls | `/calls/v1/connect` WebSocket | `/etc/elo/call/config.json` |
| LiveKit | For group media and call admission | `/media/` WebSocket plus its ICE ports | `/etc/elo/media/livekit.yaml` |
| coturn | For direct calls across restrictive networks | `turn.example.org:3478/5349` plus relay ports | `/etc/elo/turn/turnserver.conf` |
| `elo-wake` | For message and invitation push notifications | `/v1/routes/`, `/wake/health` | Firebase service account; APNs key configured in Firebase for iOS |

For a minimal messages-and-files installation, complete the host, local storage, TLS and client-build steps first. To offer **all** app features, complete the call and wake sections too. The app does not silently provide publisher-operated services when your own endpoint is unavailable.

## 2. VPS and build prerequisites

1. Create a VPS with a public IPv4 address, Debian 13 or Oracle Linux 10, working time synchronization and enough disk for data plus backups. Create DNS A records for `chat.example.org` and `turn.example.org` pointing to it. Set up SSH access using the operator's own account and key.
2. Install a C/C++ build toolchain, Git, curl, OpenSSL, Python 3, Nginx, Certbot and coturn from trusted distribution or upstream repositories. On Debian 13 the starting packages are:

   ```sh
   sudo apt update
   sudo apt install build-essential pkg-config cmake clang perl git curl ca-certificates openssl nginx certbot coturn
   ```

   On Oracle Linux 10 use `dnf` for `gcc gcc-c++ make pkgconf-pkg-config cmake clang perl git curl ca-certificates openssl nginx`, then install Certbot and coturn from repositories supported for that host. Check availability with `dnf info certbot coturn` before continuing. Keep SELinux enforcing. Allow Nginx to connect to the loopback upstreams using the distro's `httpd_can_network_connect` policy only after reviewing its scope; do not turn off SELinux or the firewall.
3. Install Rust with [rustup](https://rust-lang.org/tools/install/) for the build account. From the checked-out source, `rustup` selects the exact version in `rust-toolchain.toml`. Build and install the three elo services:

   ```sh
   cargo build --release --locked -p elo-team -p elo-call-service -p elo-wake
   sudo install -d -m 0755 /opt/elo/bin
   sudo install -m 0755 target/release/elo-team /opt/elo/bin/elo-team
   sudo install -m 0755 target/release/elo-call-service /opt/elo/bin/elo-call-service
   sudo install -m 0755 target/release/elo-wake /opt/elo/bin/elo-wake
   ```

4. Install a pinned, checksum-verified [LiveKit Server release](https://github.com/livekit/livekit/releases) for your CPU architecture as `/opt/elo/bin/livekit-server`. The tested development deployment used LiveKit 1.13.7; newer versions need their own acceptance run. Install coturn from the OS package or a verified upstream release. Check `/opt/elo/bin/livekit-server --version` and `turnserver --version`. Do not use a floating `latest` image for an unattended production upgrade.

Open inbound TCP 22 for managed SSH access, TCP 80/443 for HTTPS and certificate renewal, UDP 7882 and TCP 7881 for LiveKit ICE, UDP/TCP 3478 and TCP 5349 for TURN, and UDP 49160–49200 for TURN relays. Allow them in both the VPS provider firewall and the operating-system firewall. LiveKit's API port 7880 and elo's 18900, 18901, 18920, 8788 and 8794 ports must remain private. If a VPS is behind NAT, configure its public address in LiveKit/coturn and verify it from a different network. See the [LiveKit port reference](https://docs.livekit.io/transport/self-hosting/ports-firewall/).

## 3. Service accounts, directories and shared secrets

Create four unprivileged users (`elo-host`, `elo-call`, `elo-wake`, `elo-media`) and one user for coturn if the package did not create it. Give each service its own data/configuration directories. For example, as an administrator on either distribution:

```sh
for name in elo-host elo-call elo-wake elo-media; do
  sudo useradd --system --no-create-home --shell /usr/sbin/nologin "$name"
done
sudo install -d -m 0755 /etc/elo /var/lib/elo
for name in host call wake media; do
  sudo install -d -m 0700 -o "elo-$name" -g "elo-$name" "/etc/elo/$name" "/var/lib/elo/$name"
done
sudo install -d -m 0700 -o elo-host -g elo-host /var/lib/elo/attachments
```

If the OS has a different `nologin` path or the account already exists, adjust those commands instead of creating a second account. The data directories must be owned by that service user with mode `0700`; private config and key files must be regular files with mode `0600`, owned by the user that reads them. The Rust services reject world/group-readable private files. After writing each example config, install it with `sudo install -m 0600 -o SERVICE_USER -g SERVICE_USER SOURCE /etc/elo/SERVICE/config.json`; use a matching file name for YAML and keys. Keep temporary source files outside the Git checkout and remove them after installation.

Recommended paths:

| Owner | Private files | Writable data |
| --- | --- | --- |
| `elo-host` | `/etc/elo/host/config.json`, `admission.key` | `/var/lib/elo/host`, `/var/lib/elo/attachments` |
| `elo-call` | `/etc/elo/call/config.json`, `admission.key`, `wake.key` | `/var/lib/elo/call` |
| `elo-wake` | `/etc/elo/wake/firebase.json`, `calls.key`, optional `apns.json` and `.p8` | `/var/lib/elo/wake` |
| `elo-media` | `/etc/elo/media/livekit.yaml` | `/var/lib/elo/media` |
| coturn user | `/etc/elo/turn/turnserver.conf`, TLS key/certificate | coturn's own state/log directory |

Generate **three independent** 32-byte random secrets as 64 lowercase hexadecimal characters, without a trailing newline: one for host ↔ call admission, one for call ↔ wake delivery, one for TURN REST authentication. For each secret, `openssl rand -hex 32 | tr -d '\n'` produces the required format. Copy the admission secret into separate `0600` files owned by `elo-host` and `elo-call`; likewise copy the call-delivery secret into separate `0600` files owned by `elo-call` and `elo-wake`. Do not use a group-readable shared file: `read_private` rejects it. Put the TURN secret in coturn's config and the call service's `media.turn_secret`. Do not reuse any of these three secrets as a LiveKit key.

## 4. Hosted Spaces and encrypted attachments

Save the following as `/etc/elo/host/config.json` (mode `0600`, owned by `elo-host`). The local provider is the simplest full attachment setup on one VPS:

```json
{
  "root": "/var/lib/elo/host",
  "public_url": "https://chat.example.org",
  "max_spaces_per_identity": 2,
  "max_spaces": 128,
  "max_space_creations_per_day": 32,
  "mailbox_quota_bytes": 150000000,
  "call_admission_key": "/etc/elo/host/admission.key",
  "backup_access_key": "/etc/elo/host/backup-access.key",
  "attachment_storage": {
    "provider": "local",
    "root": "/var/lib/elo/attachments"
  }
}
```

`public_url` must be the final HTTPS origin **without a trailing slash**. The host builds signed, Space-specific `/spaces/{id}/replica/` and enrollment endpoints under that origin. A client keeps the signed endpoint and signing-key pin after joining. Do not round-robin the host over independent databases. This example allows two Spaces per creator, with 150,000,000 encrypted-message bytes and a separate 50,000,000-byte encrypted-attachment quota per Space. Each plaintext file is limited to 5 MiB. The deployment-wide limits also count new identities: at most 128 allocated Spaces and 32 new reservations per UTC day by default. Lower these values to fit the disk budget; 128 fully used Spaces require at least 25.6 GB before overhead. Retries of an existing reservation do not spend another daily slot. These caps bound resource consumption; they do not prove that two profiles belong to different people.

The next-release baseline also requires a 20-bit SHA-256 proof of work tied to
each signed Space-creation request. The client computes it locally on a worker;
the host verifies it before signature checks and provisioning. This adds work
only when creating a Space, with no extra request or proof on ordinary messages.
The host additionally limits new reservations to four per UTC day per IPv4 address
or IPv6 /64, across identities. The persisted daily budget survives restarts;
deleting a Space does not refund that day's slot. Shared networks share this
limit, together with a maximum of eight existing Spaces attributed to that network.
The daily budget and network attribution survive restarts. Existing reservations
without network attribution retain their access. The allocation index includes
interrupted reservations; network capacity checks read only the bounded reservation
metadata, never every profile database.

Use `proxy_set_header X-Real-IP $remote_addr;` in the hosting proxy, as in the
supplied Nginx examples. The backend trusts this header only from loopback and
otherwise uses the TCP peer address. Keep the backend private; do not forward
an untrusted incoming `X-Real-IP`. Daily network keys are SHA-256 hashes of the
address/prefix, not an anonymity guarantee. Omitting the header behind a local
proxy makes all its clients share one creation budget.

Space administration is stored in `space-service.sqlite` inside the service
profile. Rows are encrypted individually with XChaCha20-Poly1305 and an
authenticated manifest detects row deletion or substitution. A transaction
updates only changed rows. The database is bounded to 256 MiB and 32,768 data
rows; each row retains an 8 MiB limit. Loading still validates the entire state.
An old `space-service.age` is imported on first successful save and then removed;
this storage conversion does not make older clients protocol-compatible.
Back up the complete service profile while stopped, not just this file. Local
encryption does not prevent an operator from restoring an entire older backup.

Pending join requests have separate bounds: 256 per Space, 32 per invitation,
four per identity, and a seven-day lifetime. Revoking/expiring the invitation
also frees its pending requests. Uploads have 16 unfinished slots per identity
and 4,096 metadata entries per Space; terminal metadata (deleted, expired or missing) is pruned as
documented in the attachment implementation. These bounds are independent of
the attachment byte quota.

To use MEGA instead of the VPS disk, install [MEGAcmd](https://github.com/meganz/MEGAcmd) under a separate local user, log it into **your own** MEGA account without putting credentials in source or a process command line, create a dedicated folder, and expose that folder with MEGAcmd's [WebDAV command](https://github.com/meganz/MEGAcmd/blob/master/contrib/docs/WEBDAV.md). Keep WebDAV on loopback; never use `--public`. Replace only `attachment_storage` with:

```json
{"provider":"mega_web_dav","base_url":"http://127.0.0.1:4443/<MEGAcmd-generated-private-path>"}
```

Use the exact URL returned by MEGAcmd, keep the MEGAcmd process running, and verify upload/download/delete before accepting users. The URL is a local gateway path, **not** the MEGA login or a public share link. MEGAcmd itself holds the MEGA session.

For S3-compatible storage, create a dedicated bucket and least-privilege access key with object put/get/delete rights, then replace the provider with `{"provider":"s3_compatible","endpoint":"https://s3.example.org","region":"REGION","bucket":"BUCKET","access_key":"KEY","secret_key":"SECRET"}`. The access and secret keys remain only in the private host config. Do not configure multiple providers at once; changing providers requires moving existing objects or accepting their loss.

Start the host on loopback:

```sh
/opt/elo/bin/elo-team host --config /etc/elo/host/config.json --bind 127.0.0.1:18900
```

The process also binds a private operator listener at `127.0.0.1:18901`. Calls use only its `/internal/calls/admission` route. Backup inventory and ciphertext exports require a separate `backup_access_key`: exactly 64 lowercase hexadecimal characters (256 random bits), in a mode-0600 file readable by hosting and the root backup job. Without that configured key, backup routes return 404; missing or incorrect bearer authorization returns 401. Do not reuse the call-admission key. **Never proxy or expose port 18901 publicly.**

## 5. LiveKit, TURN and call control

Create `/etc/elo/media/livekit.yaml` (private to `elo-media`) with the same LiveKit API key/secret that you will set in the call service. The API secret must be at least 32 characters:

```yaml
port: 7880
rtc:
  tcp_port: 7881
  udp_port: 7882
  use_external_ip: true
keys:
  elo-self-host: "REPLACE_WITH_INDEPENDENT_RANDOM_LIVEKIT_SECRET"
```

Put TCP 7880 behind the `/media/` TLS proxy, not on the public firewall. LiveKit advertises the public VPS IP for its ICE candidates. If automatic external-IP discovery is wrong, set the actual public address using the option documented in the [LiveKit sample configuration](https://github.com/livekit/livekit/blob/master/config-sample.yaml). Run one LiveKit instance for this single-VPS installation; do not add Redis or a second media node here.

Create a private coturn config with the **same** TURN secret used by the call service. Use the DNS name `turn.example.org`, and copy its certificate/key into files readable by the coturn service account:

```ini
realm=turn.example.org
fingerprint
use-auth-secret
static-auth-secret=REPLACE_WITH_TURN_SECRET
listening-port=3478
tls-listening-port=5349
min-port=49160
max-port=49200
cert=/etc/elo/turn/fullchain.pem
pkey=/etc/elo/turn/privkey.pem
no-multicast-peers
# Keep allow-loopback-peers disabled.
no-tcp-relay
denied-peer-ip=0.0.0.0-0.255.255.255
denied-peer-ip=10.0.0.0-10.255.255.255
denied-peer-ip=100.64.0.0-100.127.255.255
denied-peer-ip=127.0.0.0-127.255.255.255
denied-peer-ip=169.254.0.0-169.254.255.255
denied-peer-ip=172.16.0.0-172.31.255.255
denied-peer-ip=192.168.0.0-192.168.255.255
denied-peer-ip=::1
denied-peer-ip=fc00::-fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
denied-peer-ip=fe80::-febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff
```

The peer restrictions follow the [coturn configuration reference](https://github.com/coturn/coturn/blob/master/examples/etc/turnserver.conf). They block relay access to private and link-local services, including common cloud metadata addresses. `no-tcp-relay` disables TCP connections to peers; clients can still connect to TURN over TCP/TLS. For the host's public addresses, restrict relay egress with a firewall to the media UDP ports that are actually needed. Do not deny those addresses wholesale when LiveKit or another TURN participant uses them: that would break valid calls. Keep administration services private and test a forced TURN connection from a different network before deploying these restrictions.

If the VPS has NAT, configure coturn's external/public IP mapping as documented by [coturn](https://github.com/coturn/coturn/wiki/turnserver). Reload or restart coturn after TLS certificate renewal. TCP 5349 avoids colliding with Nginx's TCP 443 on one IP; test a forced-TURN call from another network, because a successful local call does not verify the relay.

Run coturn under its packaged, unprivileged service account. For the unprivileged
ports above, install `deploy/self-host/coturn-hardening.conf` as
`/etc/systemd/system/coturn.service.d/elo-hardening.conf`, run
`sudo systemctl daemon-reload`, and restart coturn during the rollout window.
The drop-in removes Linux capabilities, prevents privilege escalation and makes
system/home paths read-only or inaccessible. Check certificate/config ownership
first and repeat forced-relay tests over UDP, TCP and TLS after applying it.
Do not apply this unchanged to privileged listeners such as port 443.

Save `/etc/elo/call/config.json` (private to `elo-call`) with the same LiveKit pair and TURN secret. `wake` may be omitted until the wake service is ready:

```json
{
  "bind": "127.0.0.1:18920",
  "public_url": "https://chat.example.org/calls/v1",
  "data": "/var/lib/elo/call",
  "admission_url": "http://127.0.0.1:18901/internal/calls/admission",
  "admission_key": "/etc/elo/call/admission.key",
  "max_connections": 128,
  "media": {
    "url": "wss://chat.example.org/media/",
    "api_url": "http://127.0.0.1:7880",
    "api_key": "elo-self-host",
    "api_secret": "REPLACE_WITH_SAME_LIVEKIT_SECRET",
    "turn_urls": [
      "turn:turn.example.org:3478?transport=udp",
      "turns:turn.example.org:5349?transport=tcp"
    ],
    "turn_secret": "REPLACE_WITH_SAME_TURN_SECRET"
  }
}
```

The `admission_key` must have exactly the same 64 characters as the host's `call_admission_key`. The call service reads its JSON with `--config /etc/elo/call/config.json`. Its public WebSocket is only `/calls/v1/connect`; the private admission URL must stay on loopback. Media credentials are issued to clients as short-lived tokens through signed call operations, not baked into an app package.

## 6. Firebase, APNs and the wake service

Create your own Firebase project with Android and iOS apps matching the identifiers in **your** client build. Download the Android `google-services.json` and iOS `GoogleService-Info.plist` as private build inputs. Enable Cloud Messaging, associate APNs credentials with the iOS Firebase app for ordinary message notifications, and create a restricted Firebase service-account key for the VPS. The service account JSON belongs at `/etc/elo/wake/firebase.json`, readable only by `elo-wake`. See [Firebase's server-environment guide](https://firebase.google.com/docs/cloud-messaging/server-environment).

iOS uses the APNs credentials associated with Firebase for ordinary notifications.
Chat audio/video sessions are joined in the foreground and do not use CallKit,
PushKit, a separate APNs VoIP key or VoIP-token App Attest enrollment.

Start the wake service with the same public origin as the host:

```sh
/opt/elo/bin/elo-wake \
  --service-account /etc/elo/wake/firebase.json \
  --database /var/lib/elo/wake/wake.sqlite \
  --public-url https://chat.example.org \
  --listen 127.0.0.1:8788
```

Before starting the daemon, `elo-wake --service-account /etc/elo/wake/firebase.json --check-authentication` validates Firebase authentication without sending a notification. Ordinary push routes are public only through the TLS proxy.

When upgrading from ringing calls, remove the call service's `wake` block and
`limits.ring_timeout`, plus the wake service's `--call-key`, `--call-listen` and
`--apns-config` arguments. The relay removes retired call/VoIP tables while retaining
ordinary routes and message queues. Clients and call service must be deployed
together: session signaling now requires an epoch in the signed message and envelope.
Do not update a server used by a reviewer running the previous client until the
matching client rollout is ready.

## 7. Keep the services running

Install the supplied, editable systemd examples: [host](../deploy/self-host/elo-host.service), [call control](../deploy/self-host/elo-call.service), [LiveKit](../deploy/self-host/elo-media.service), and [wake](../deploy/self-host/elo-wake.service). Replace `chat.example.org` in the wake unit and review paths if you chose non-default locations. On the VPS, copy each to `/etc/systemd/system/` under the same file name. The units use unprivileged users, private data paths, restart on failure and filesystem restrictions. Run coturn under its packaged service or a dedicated equivalent.

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now elo-host.service elo-media.service elo-wake.service elo-call.service
sudo systemctl status elo-host.service elo-media.service elo-wake.service elo-call.service
```

For a messages-only installation, enable only `elo-host.service`; the wake unit requires Firebase and the example call unit requires LiveKit. Check startup failures with `journalctl -u SERVICE -n 100 --no-pager`. Do not log secret files or request bodies. Restart a unit after changing its private configuration; run `systemctl daemon-reload` after changing a unit file.

## 8. TLS reverse proxy

First obtain trusted certificates for both DNS names. Create `/var/www/letsencrypt`, configure an HTTP port-80 server with a `/.well-known/acme-challenge/` webroot at that directory, then issue separate certificates for each name with Certbot. The example [Nginx configuration](../deploy/self-host/nginx.conf.example) includes that HTTP server; enable its port-80 block first, with the TLS block withheld until certificates exist. For example:

```sh
sudo install -d -m 0755 /var/www/letsencrypt
sudo nginx -t && sudo systemctl reload nginx
sudo certbot certonly --webroot -w /var/www/letsencrypt -d chat.example.org
sudo certbot certonly --webroot -w /var/www/letsencrypt -d turn.example.org
```

Then enable the full example in Nginx's `http` context, replace the domains, and run `sudo nginx -t && sudo systemctl reload nginx`. Ensure the distribution's default site does not intercept the app domain. Keep the HTTP challenge route for renewal and check it with `sudo certbot renew --dry-run`. The TLS server for `chat.example.org` on TCP 443 has these **allowlisted** route families:

| Route | Upstream |
| --- | --- |
| `/spaces/v1/create`, `/spaces/v1/health`, `/accounts/v1/deletion`, `/accounts/v1/deletion/status` | `http://127.0.0.1:18900` |
| `/hosting/v1/realtime` | `http://127.0.0.1:18900`; exact path, WebSocket Upgrade, buffering off and long read timeout |
| `/spaces/<64-lowercase-hex-id>/team/v1/spaces` | `http://127.0.0.1:18900` |
| `/spaces/<64-lowercase-hex-id>/replica/...` | `http://127.0.0.1:18900`, **preserve the full path** |
| `/spaces/<64-lowercase-hex-id>/attachments/v1/upload` and `download` | `http://127.0.0.1:18900`; 6 MiB upload body limit, request buffering off, 125 s transfer timeout |
| `/v1/routes/...`, `/wake/v1/account-deletion`, `/wake/health` | `http://127.0.0.1:8788` |
| `/calls/v1/connect`, `/calls/v1/health` | `http://127.0.0.1:18920`; WebSocket Upgrade and long read timeout |
| `/media/...` | `http://127.0.0.1:7880/...`; **strip only** the `/media/` prefix, retain WebSocket Upgrade |

The supplied Nginx example keeps `Host` and `Authorization` headers, disables upstream retry and caching, and logs only request metadata rather than body/path. Return 404 for every other path. Nginx's `proxy_pass` behavior differs between prefix and regex locations: check the **actual** upstream URI in your config before starting. A normal `GET /spaces/v1/health` must reach the host unchanged. Public `/internal/calls/admission` and `/internal/calls/event` must return 404. Review and add suitable per-IP rate limits before accepting untrusted traffic; the publisher's [hosting proxy example](../deploy/self-host/hosting-rate-limits.conf.example) shows tested limit zones and burst settings.

The live message route is separate from call control and LiveKit. The current
Nginx examples include its exact location with HTTP/1.1, `Upgrade` and
`Connection: upgrade`, a 3,600-second read timeout, no buffering/cache/upstream
retry, and per-IP handshake/connection limits. Preserve `Host` and the complete
`/hosting/v1/realtime` path; do not put this route under
`/spaces/<id>/replica/` or strip `/hosting/`. The native client uses WebSocket
ping/pong and reconnects with bounded backoff. Authentication occurs in signed
subscription frames after the upgrade; do not put tokens in URLs or log frames.
An HTTP health check or a successful 101 upgrade is not proof that mailbox
subscription is authorized.

For a **standalone Replica** installation, use the exact `/v1/realtime` route
from its [proxy example](../deploy/replica/nginx.conf.example), forwarding to
that Replica's private listener (the example uses `127.0.0.1:8787`). It is not
the hosted route and must receive the same Upgrade/timeout treatment. A blocked
socket or older service leaves ordinary HTTP synchronization available at its
fallback cadence; typing, online dots and remote upload previews then may be
unavailable. Live subscriptions use the same signed access and revocation checks
as durable synchronization. Ephemeral envelopes are encrypted for participants;
the relay still observes subscriptions, recipient identities, timing and sizes.
They carry typing, presence and upload activity, not attachment file bytes.
Typing and presence expire when updates stop. The relay bounds frames,
subscriptions, connection counts and outgoing queues; slow consumers reconnect
and recover durable messages through ordinary synchronization. These transient
indicators are not a delivery or read receipt.
The examples are source configuration, not evidence that these new routes have
been deployed or verified through a particular production proxy.

The certificate for `turn.example.org` is used directly by coturn's TLS listener on TCP 5349, not by the application Nginx server. Copy its renewed certificate and key into the private coturn paths and restart coturn from a Certbot deploy hook. Confirm that renewal does not expose the private key to other service users.

## 9. Build and connect a client

Build the desktop or mobile app from this source with **one** endpoint override in its build environment:

```sh
export TAURI_ELO_API_URL=https://chat.example.org
```

This value is compiled into the client; there is no VPS username/password field in the app. Do **not** set `TAURI_ELO_SPACE_HOST_URL` or `TAURI_ELO_WAKE_URL` together with it. Desktop build commands and native iOS/Android initialization are in [BUILDING.md](BUILDING.md). Mobile builds with notifications must enable the `mobile-push` feature and supply `TAURI_ELO_FIREBASE_ANDROID` / `TAURI_ELO_FIREBASE_IOS` as appropriate. The client app IDs, Firebase apps, Apple entitlements, signing identities and APNs `bundle_id` must match for the target deployment. Builds without these matching provider settings can still use messages, but not mobile push notifications.

Create a new profile, create a Space, share its invitation with a **second, independent profile**, approve its join request, and exchange messages. Keep an authorized owner device online until it commits the new General membership. The owner manages General; the host does not create a readable service profile for it. Existing Spaces from another installation do not move merely because the app's build-time origin changes; joining relies on signed Space endpoints and key pins.

## 10. Acceptance, backup and operations

Before giving the service to users:

1. Check external HTTPS with normal certificate verification: `GET /spaces/v1/health` returns 200; `GET /calls/v1/health` and `GET /wake/health` return 204 when those services are enabled. The operator-only paths return 404 publicly. Check that the non-public listeners are not reachable from another machine.
2. On real devices, test Space creation and join approval, encrypted messages, a 5 MB attachment upload/download/cancel, two-person and three-person audio/video sessions, a forced TURN connection from another network, and a push while the app is closed. Join sessions from the chat and verify audio after backgrounding each final signed mobile build, leaving, ending and joining again. For live messages, verify an authenticated socket subscription through public TLS, immediate catch-up after reconnect, typing expiry, foreground-only online dots across two devices of one profile, and remote upload completion/cancellation/interruption. Block the socket temporarily to verify HTTP fallback and restore it to verify catch-up. Remove/revoke a subscribed identity/device and check that it loses live access, including queued events, without cross-Space leakage.
3. Test account deletion, Space deletion, backup export/recovery and a service restart. Verify the stated two-Space/150 MB message/50 MB attachment limits against the running service. Watch disk and inode usage, TLS expiry, errors 429/503/507, and service restarts.
4. Back up the complete `/var/lib/elo/host` tree and the attachment provider's objects together using the coordinated online snapshot below, or a complete stopped copy. Also protect wake state, call database, private service configs and keys. A live SQLite main file alone is not a consistent backup. A restore of stale membership/deletion state is not safe to automate. Rehearse recovery on an isolated host before promising it to users.

This guide defines a reproducible **configuration layout**, but is not evidence that a particular VPS or package was accepted. Debian 13, Oracle Linux 10, every chosen storage provider, provider credentials, DNS/TLS and final signed mobile apps require validation on the actual installation. The publisher's private deployment scripts, credentials and multi-server routing are deliberately not included.

## Encrypted operational backups

`deploy/hosting/backup.py` and `elo-backup.{service,timer}` provide daily age-encrypted operational snapshots for a systemd deployment. Install `age` and `curl`. Generate the age identity on an administrator's separate machine; keep an independent recovery copy there. Put **only its public recipient** in `/etc/elo-backup/recipient.txt` on the server. Never include the age identity in a source archive, VPS configuration or backup job.

Create a root-owned mode-0600 `/etc/elo-backup/config.json` with:

```json
{
  "recipient_file": "/etc/elo-backup/recipient.txt",
  "paths": ["/var/lib/elo/host", "/var/lib/elo/wake", "/var/lib/elo/call", "/etc/elo"],
  "destination": "/var/backups/elo-operations",
  "offsite_url": "http://127.0.0.1:18930/REPLACE_WITH_PRIVATE_COLLECTION/operations-backups",
  "retention_days": 7,
  "attachments": {
    "operator_url": "http://127.0.0.1:18901",
    "access_key_file": "/etc/elo/host/backup-access.key",
    "max_bytes": 1073741824
  }
}
```

Adapt paths to the deployment; every listed path must exist and use canonical directory components without symlinks. Privileged runs accept only the fixed `/etc/elo-backup/config.json`, which must be a root-owned mode-0600 regular file; a caller cannot select a different config with `--config`. Install the scripts and their parent directories as root-owned and not writable by service users. Install `backup.py`, `online_snapshot.py` and `attachment_snapshot.py` together in `/opt/elo/hosting/`, create the destination directory with mode 0700, install the units, run `systemctl start elo-backup`, and verify its successful result before enabling `elo-backup.timer`.

Snapshots use SQLite's online backup API, including committed WAL data. Persistent database observers and before/after file inventories reject a capture that overlaps a committed write, file replacement, deletion or configuration change. The job retries three times; sustained writes can make the backup fail rather than publish inconsistent state. It never stops application services. Plain staging files live only in a private temporary directory under the backup destination and are removed after encryption or failure; service-manager cleanup and the next locked job remove interrupted staging after a forced termination or machine shutdown. Allow free disk for staging plus encrypted output. Each capture has a two-minute budget. The timer runs daily; VPS and MEGA retention is seven days. Old local snapshots are pruned only after a new capture succeeds. Failed transfers remain local for retry. Inspect `systemctl status elo-backup` and the last successful off-site object; an enabled timer is not proof of a successful backup.

For an independently controlled copy, run `pull_backup.py --config /private/path/pull.json` on an administrator's computer with `age` and SSH available. Example private configuration:

```json
{
  "host": "operator@your-vps.example",
  "ssh_key": "/private/path/server-ssh-key",
  "age_key": "/private/path/offline-backup.agekey",
  "age": "/usr/local/bin/age",
  "destination": "/private/path/independent-backups",
  "required_paths": ["/var/lib/elo/host", "/var/lib/elo/wake", "/var/lib/elo/call", "/etc/elo"],
  "require_attachments": true
}
```

Keep this configuration and destination private. SSH host-key verification is mandatory and agent forwarding is disabled. Schedule the pull on that separate computer, not from the VPS. The server receives no access to the local directory or decryption key. Remote deletion never propagates locally.

Age decryption verifies ciphertext integrity, **not who created a snapshot**: anyone with the server's public recipient can encrypt replacement data. The pull therefore never automatically deletes independent copies. Its bounded checks verify archive structure, the locally configured `required_paths`, and every attachment's length and SHA-256 against the manifest, without extracting archive paths. These checks detect missing or corrupt contents, but do not authenticate a compromised server's state. Keep older recovery points until an operator rehearses recovery and explicitly retires them; remote snapshots must not authorize pruning. This is not immutable cloud storage or an offline key copy.

Each run fetches only the newest remote snapshot. The inventory is limited to 256 KiB; transfers are bounded to 2 GiB per archive and five minutes. Archive validation has a two-minute budget, 100,000-member limit and 8 GiB expanded-byte bound. The pull stops before its local directory exceeds 8 GiB or free disk falls below a 2 GiB reserve. It preserves all existing copies when these limits prevent a download. Plan independent capacity and monitor successful pulls. `required_paths` must match the server's configured snapshot roots; set `require_attachments` to false only for an intentionally state/configuration-only backup.

A dedicated backup reader needs only the exact encrypted export commands. For sudo 1.9.10 or newer, a scoped policy can use argument regular expressions (adapt only the account name):

```sudoers
Cmnd_Alias ELO_BACKUP_READ = /usr/bin/python3 /opt/elo/hosting/backup.py --list-encrypted, /usr/bin/python3 ^/opt/elo/hosting/backup[.]py --read-encrypted elo-ops-[0-9]{8}T[0-9]{6}Z[.]tar[.]gz[.]age$
elo-backup-reader ALL=(root) NOPASSWD: ELO_BACKUP_READ
```

Validate the policy with `visudo -cf` and test that `--config`, arbitrary Python, snapshot creation and extra arguments are rejected. Never delegate `/usr/bin/python3` or a wildcard `backup.py *`. Keep the script, imported helper modules and every parent directory root-owned and non-writable by the reader. The fixed-config restriction is defense in depth, not a replacement for the scoped sudo policy.


With `attachments` configured, the archive also includes the **encrypted attachment bytes** under `elo-attachments/spaces/<space>/<object>` and a manifest. The loopback operator API lists committed uploads and available attachments, never plaintext filenames or decryption keys. The job streams them through the configured storage provider, verifies each length and SHA-256, captures the databases, and checks that the complete attachment metadata has not changed. A reservation is omitted from the attachment inventory only before any configuration or invitation was published. An unavailable configured Space, missing/corrupt object, concurrent change or exhausted budget fails the snapshot instead of publishing an incomplete copy. Deleting, expired, already deleted and known-missing objects are not restorable attachments and are excluded; reserved uploads are not yet committed. New metadata invalidates the before/after check, including objects that were subsequently deleted during capture.

The default attachment budget is 1 GiB per attempt, with a ten-minute transfer budget, a 6 MiB per-object bound and a 2 GiB free-disk reserve. Configure sufficient space for staging, archive output and independent retention; the total allocation limit of the hosting service can exceed this backup budget. Sustained attachment mutations can exhaust the three attempts. Monitor actual successful backups. Omitting `attachments` intentionally makes a state/configuration-only backup. This is not a full operating-system image.

After decryption on an isolated restore host, verify every manifest size and SHA-256 again. Restore the ciphertext tree to the selected provider's `spaces/<space>/<object>` keys, preserving object IDs, before starting hosting with the matching database snapshot and compatible binary. Restore all retained objects even if their expiry is in the past; normal service retention will remove expired data. Do not infer recoverability from an archive containing only metadata. The separate computer's pull and retention protect an already downloaded archive from deletion on the VPS or MEGA; a copy still stored only in MEGA shares the provider failure domain. Download a copy independently of the VPS and rehearse decryption with `age --decrypt --identity /secure/offline-backup.agekey snapshot.tar.gz.age`. Validate every SQLite database, then start the restored service on a network-isolated host with matching binaries and a rewritten local storage root. Do not expose restored listeners or publish stale membership. Preserve/reapply all newer deletion receipts, revoked-device records and account-erasure requests before returning restored state to service.

Owner-managed General v2 has no hosting-side General vault, private message keys
or `service-recovery.age` card. Operational backups protect public authority state
and the host's separate response/replica signing material; they do not recover an
owner's private profile. Keep owner-device backups and recovery material under
the owner's control. An already authorized linked owner device can manage General
after another owner device is revoked. Losing every authorized owner device
still requires the explicit management-recovery process.

The host shares four SQLite worker slots across profiles. The notification relay uses a dedicated SQLite worker with at most 64 queued operations; overload returns HTTP 503. SQLite never runs on the relay's network executor, and provider requests remain outside the database worker. Recipient policy changes and delivery retain their original ordering. A corrupt Space stays unavailable and consumes its allocation, while healthy Spaces continue serving. Deletion tombstones remain permanent; completed cleanup is recorded so a restart does not contact attachment storage for it. HTTP deletion and subsequent requests return the durable signed receipt without contacting attachment storage or acquiring the creation lock. Access closes immediately; physical cleanup retries only in the background. The defaults admit 128 Spaces, 32 creations per deployment/day and four per IPv4 address or IPv6 /64/day, alongside the two-Space identity limit. These are capacity/abuse budgets, not proof of a unique human. New reservations can be reclaimed after 24 hours only if all invitations have expired and no authenticated use or join request was ever accepted. The claim marker is permanent, including after a pending request expires or a member leaves. Previously existing advertised Spaces and damaged/unavailable state are never inferred to be unused. This is not inactivity-based deletion. Eight existing Spaces per network supplement the daily limits, but an attacker using many independent networks can still exhaust anonymous capacity. `/stats` reports allocated, remaining and near-full capacity (80% threshold); outbound alerts require separate operator configuration.

### Isolate the local attachment bridge

A loopback bind is not authorization between local users. The backup bearer key authenticates the caller, not the local server process: another user able to bind an unavailable port can impersonate its listener. Protect port ownership with separate network namespaces or an authenticated local transport before treating that boundary as isolated. The online SQLite capture still parses service-owned databases in the backup process; the no-follow regular-file reads do not sandbox SQLite or eliminate its path-based open race. Moving database capture into a restricted service-UID worker remains necessary for a hostile-local-service threat model. Restrict MEGA's WebDAV port to the hosting service UID, attachment daemon UID and root using an nftables output rule. Cover both `127.0.0.1` and `::1`, persist it with the existing firewall configuration, and verify that a request as `elo-wake` or `elo-call` is rejected while hosting still works. Do not expose or log the private WebDAV collection URL. Bound wake and MEGA service memory and task counts as well as the hosting service. Keep key-only SSH, disable root/password/X11 access after testing a separate key connection, and retain a guarded rollback until that check succeeds.

## Coordinated device-security upgrade

Deploy matching clients, `elo-team` and Replica code when enabling access proofs v2. Old proofs and pairing links are rejected; upgrading only the server interrupts old clients. The hosted service derives its trusted public origin from `public_url`. For a standalone Replica behind TLS, pass `--public-origin https://your-replica.example` while retaining its loopback bind and `--allow-insecure-loopback`. Forward the original URI unchanged; do not derive origin from request headers.

Back up the host root's `revoked-devices/` together with all Space state and Replica databases. The signed device tombstones are permanent and shared across Spaces, including subsequently created ones. Never prune them to free space or restore an older registry while retaining newer app state. A full registry refuses additional entries. The Replica nonce table is durable too; copying or restoring live database files outside the documented SQLite backup process is unsafe.

Before production rollout, verify pairing with independent credentials, interrupted root-code recovery, revoked-device denial after server restart, private-chat recipient updates, and offline host retries. Existing devices that shared one credential must be linked again to receive independent credentials; the server cannot distinguish old copies of the same key. Keep the original controller available until private chats have adopted the new device, or use the explicit controller-recovery process.
