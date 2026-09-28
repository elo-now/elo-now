# Self-host elo.now on one VPS

This guide is for a **new, empty installation** on Debian 13 or Oracle Linux 10. It uses one VPS and one public application origin. It covers hosted Spaces and encrypted messages, attachments, voice/video calls, and optional mobile notifications/background calls. There is no migration from the publisher's installation and no requirement for `api.elo.now`.

The examples use `chat.example.org` for the app API and media WebSocket, and `turn.example.org` for TURN on the same VPS. Replace both names throughout. Keep all private files and credentials **outside the source checkout**. Never put an SSH password, MEGA password, Firebase service account, APNs key, LiveKit secret or TURN secret in the mobile/desktop app.

Debian 13 is the deployment path exercised by this project. Oracle Linux 10 follows the same service layout, but still requires its own end-to-end acceptance run, especially package availability, SELinux policy and media ports. Do not present an untested OEL10 installation as verified.

For upgrades to an existing installation, read [API compatibility and application updates](API_COMPATIBILITY.md) first. The current security baseline is a clean cutover with matching clients and services, without older-client support or existing-data migration; this guide is not an in-place migration procedure. The optional `client_policy` field in `/etc/elo/host/config.json` controls platform minimums. Leave them disabled until the replacement app is available to users.

## 1. What runs where

| Component | Install on the VPS | Public route / port | Private configuration |
| --- | --- | --- | --- |
| Nginx and TLS | Yes | `https://chat.example.org` on TCP 443 | TLS certificate and allowlisted proxy routes |
| `elo-team host` | Yes | Spaces, encrypted Replica and attachment gateway behind Nginx | `/etc/elo/host/config.json` |
| Attachment storage | Choose local, MEGA WebDAV or S3-compatible | No direct public storage endpoint | `attachment_storage` in the host config |
| `elo-call-service` | For calls | `/calls/v1/connect` WebSocket | `/etc/elo/call/config.json` |
| LiveKit | For group media and call admission | `/media/` WebSocket plus its ICE ports | `/etc/elo/media/livekit.yaml` |
| coturn | For direct calls across restrictive networks | `turn.example.org:3478/5349` plus relay ports | `/etc/elo/turn/turnserver.conf` |
| `elo-wake` | For mobile push and background calls | `/v1/routes/`, `/wake/health` | Firebase service account; optional APNs VoIP config |

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
The host additionally limits new reservations to 10 per UTC day per IPv4 address
or IPv6 /64, across identities. The persisted daily budget survives restarts;
deleting a Space does not refund that day's slot. Shared networks share this
limit. The allocation index is rebuilt from durable reservations at startup,
including interrupted reservations, rather than scanning every Space on each
creation.

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

The process also binds a private operator listener at `127.0.0.1:18901`. Calls use only its `/internal/calls/admission` route. **Never proxy or expose port 18901 publicly.**

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
  },
  "wake": {
    "url": "http://127.0.0.1:8794/internal/calls/event",
    "key_file": "/etc/elo/call/wake.key"
  }
}
```

The `admission_key` must have exactly the same 64 characters as the host's `call_admission_key`. The `wake.key_file` must match the wake service's `--call-key` file. The call service reads its JSON with `--config /etc/elo/call/config.json`. Its public WebSocket is only `/calls/v1/connect`; the private admission and delivery URLs must stay on loopback. Media credentials are issued to clients as short-lived tokens through signed call operations, not baked into an app package.

## 6. Firebase, APNs and the wake service

Create your own Firebase project with Android and iOS apps matching the identifiers in **your** client build. Download the Android `google-services.json` and iOS `GoogleService-Info.plist` as private build inputs. Enable Cloud Messaging, associate APNs credentials with the iOS Firebase app for ordinary message notifications, and create a restricted Firebase service-account key for the VPS. The service account JSON belongs at `/etc/elo/wake/firebase.json`, readable only by `elo-wake`. See [Firebase's server-environment guide](https://firebase.google.com/docs/cloud-messaging/server-environment).

For iOS **incoming call** delivery while the app is closed, create an APNs token-signing `.p8` key in your Apple Developer account and enable the required Push Notifications/VoIP capabilities for the iOS App ID. Save the key as `/etc/elo/wake/apns.p8` and this private config as `/etc/elo/wake/apns.json`:

```json
{
  "key_file": "/etc/elo/wake/apns.p8",
  "key_id": "YOUR10CHARID",
  "team_id": "YOUR10CHARID",
  "bundle_id": "your.app.bundle",
  "sandbox": false
}
```

Use `sandbox: true` only for development-signed iOS clients; App Store builds use production. Match `bundle_id` exactly to the signed iOS app. The APNs provider key is independent of Apple distribution-signing certificates. See [Apple's token-based APNs guide](https://developer.apple.com/documentation/usernotifications/establishing-a-token-based-connection-to-apns).

Enable App Attest for that App ID and regenerate the app's provisioning profile.
The native client reads its token from PushKit and obtains an Apple-attested key;
the relay challenges a fresh assertion bound to the route, account, endpoint and
exact token. It checks the production Apple certificate chain, application identity,
single-use challenge and increasing assertion counter. Enrollment attestation uses
a native random nonce and is cached because Apple attests a key once; the first
registration also requires a fresh server challenge assertion. No verification-only
VoIP push is sent. Unsupported devices cannot enable iOS background incoming calls.
If the signed app's App ID prefix differs from `team_id`, add `app_id_prefix` to
the APNs JSON with that ten-character prefix; otherwise it defaults to `team_id`.
The prefix, bundle ID and production App Attest entitlement must all agree.

These source changes require coordinated deployment: older clients and unproved
stored VoIP registrations cannot bypass ownership verification. Keep existing
services running until compatible signed clients have passed device acceptance.

Start the wake service with the same public origin as the host. The `--call-key` option enables its private call-delivery listener on loopback; `--apns-config` adds iOS VoIP delivery:

```sh
/opt/elo/bin/elo-wake \
  --service-account /etc/elo/wake/firebase.json \
  --database /var/lib/elo/wake/wake.sqlite \
  --public-url https://chat.example.org \
  --listen 127.0.0.1:8788 \
  --call-key /etc/elo/wake/calls.key \
  --call-listen 127.0.0.1:8794 \
  --apns-config /etc/elo/wake/apns.json
```

Before starting the daemon, `elo-wake --service-account /etc/elo/wake/firebase.json --check-authentication` validates Firebase authentication without sending a notification. Ordinary push routes are public only through the TLS proxy; `8794` is private. If APNs is not configured, remove `--apns-config` and do not claim iOS background incoming calls are supported.

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
| `/spaces/<64-lowercase-hex-id>/team/v1/spaces` | `http://127.0.0.1:18900` |
| `/spaces/<64-lowercase-hex-id>/replica/...` | `http://127.0.0.1:18900`, **preserve the full path** |
| `/spaces/<64-lowercase-hex-id>/attachments/v1/upload` and `download` | `http://127.0.0.1:18900`; 6 MiB upload body limit, request buffering off, 125 s transfer timeout |
| `/v1/routes/...`, `/wake/v1/account-deletion`, `/wake/health` | `http://127.0.0.1:8788` |
| `/calls/v1/connect`, `/calls/v1/health` | `http://127.0.0.1:18920`; WebSocket Upgrade and long read timeout |
| `/media/...` | `http://127.0.0.1:7880/...`; **strip only** the `/media/` prefix, retain WebSocket Upgrade |

The supplied Nginx example keeps `Host` and `Authorization` headers, disables upstream retry and caching, and logs only request metadata rather than body/path. Return 404 for every other path. Nginx's `proxy_pass` behavior differs between prefix and regex locations: check the **actual** upstream URI in your config before starting. A normal `GET /spaces/v1/health` must reach the host unchanged. Public `/internal/calls/admission` and `/internal/calls/event` must return 404. Review and add suitable per-IP rate limits before accepting untrusted traffic; the publisher's [hosting proxy example](../deploy/self-host/hosting-rate-limits.conf.example) shows tested limit zones and burst settings.

The certificate for `turn.example.org` is used directly by coturn's TLS listener on TCP 5349, not by the application Nginx server. Copy its renewed certificate and key into the private coturn paths and restart coturn from a Certbot deploy hook. Confirm that renewal does not expose the private key to other service users.

## 9. Build and connect a client

Build the desktop or mobile app from this source with **one** endpoint override in its build environment:

```sh
export TAURI_ELO_API_URL=https://chat.example.org
```

This value is compiled into the client; there is no VPS username/password field in the app. Do **not** set `TAURI_ELO_SPACE_HOST_URL` or `TAURI_ELO_WAKE_URL` together with it. Desktop build commands and native iOS/Android initialization are in [BUILDING.md](BUILDING.md). Mobile builds with notifications must enable the `mobile-push` feature and supply `TAURI_ELO_FIREBASE_ANDROID` / `TAURI_ELO_FIREBASE_IOS` as appropriate. The client app IDs, Firebase apps, Apple entitlements, signing identities and APNs `bundle_id` must match for the target deployment. Builds without these matching provider settings can still use messages, but not mobile push/background calling.

Create a new profile, create a Space, share its invitation with a **second, independent profile**, approve its join request, and exchange messages. Existing Spaces from another installation do not move merely because the app's build-time origin changes; joining relies on signed Space endpoints and key pins.

## 10. Acceptance, backup and operations

Before giving the service to users:

1. Check external HTTPS with normal certificate verification: `GET /spaces/v1/health` returns 200; `GET /calls/v1/health` and `GET /wake/health` return 204 when those services are enabled. The operator-only paths return 404 publicly. Check that the non-public listeners are not reachable from another machine.
2. On two real devices, test Space creation and join approval, encrypted messages, a 5 MB attachment upload/download/cancel, both direct and three-person calls, a forced TURN connection from another network, and a push while the app is closed. Check iOS and Android background call Answer/Decline separately with their final signed builds.
3. Test account deletion, Space deletion, backup export/recovery and a service restart. Verify the stated two-Space/150 MB message/50 MB attachment limits against the running service. Watch disk and inode usage, TLS expiry, errors 429/503/507, and service restarts.
4. Back up **the complete, stopped** `/var/lib/elo/host` tree and the attachment provider's objects together. Also protect wake state, call database, private service configs and keys. A live SQLite main file alone is not a consistent backup; use a coordinated stopped copy or SQLite's online-backup method. A restore of stale membership/deletion state is not safe to automate. Rehearse recovery on an isolated host before promising it to users.

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
  "retention_days": 7
}
```

Adapt paths to the deployment; every listed path must exist. Install `backup.py` and `online_snapshot.py` together in `/opt/elo/hosting/`, create the destination directory with mode 0700, install the units, run `systemctl start elo-backup`, and verify its successful result before enabling `elo-backup.timer`.

Snapshots use SQLite's online backup API, including committed WAL data. Persistent database observers and before/after file inventories reject a capture that overlaps a committed write, file replacement, deletion or configuration change. The job retries three times; sustained writes can make the backup fail rather than publish inconsistent state. It never stops application services. Plain staging files live only in a private temporary directory under the backup destination and are removed after encryption or failure; a forced machine shutdown can leave staging remnants that must be removed after investigating the failed run. Allow free disk for staging plus encrypted output. Each capture has a two-minute budget. The timer runs daily; VPS and MEGA retention is seven days. Old local snapshots are pruned only after a new capture succeeds. Failed transfers remain local for retry. Inspect `systemctl status elo-backup` and the last successful off-site object; an enabled timer is not proof of a successful backup.

For an independently controlled copy, run `pull_backup.py --config /private/path/pull.json` on an administrator's computer with `age` and SSH available. Example private configuration:

```json
{
  "host": "operator@your-vps.example",
  "ssh_key": "/private/path/server-ssh-key",
  "age_key": "/private/path/offline-backup.agekey",
  "age": "/usr/local/bin/age",
  "destination": "/private/path/independent-backups"
}
```

Keep this configuration and destination private. SSH host-key verification is mandatory and agent forwarding is disabled. The remote account needs permission to invoke the encrypted-only listing/export commands of `/opt/elo/hosting/backup.py`; use a narrowly scoped sudo policy for a dedicated backup reader. Schedule the pull on that separate computer (for example an hourly launchd agent on macOS), not from the VPS. The server receives no access to the local directory or decryption key. Remote deletion never propagates locally. Each downloaded archive is decrypted to a discard sink to check authentication before retention; at least two local copies survive retention, including during an extended outage. Review that separate retention policy against your own deletion obligations. The computer must be available regularly; this is not immutable cloud storage or an offline key copy. Transfers are bounded to 2 GiB per archive and five minutes.


This archive covers the listed state/configuration, **not attachment bytes** or a complete operating-system image. Keep attachment objects in their provider and plan a separate independent copy if protection against provider loss is required. MEGA backups and attachments share a provider failure domain. Download a copy independently of the VPS and rehearse decryption with `age --decrypt --identity /secure/offline-backup.agekey snapshot.tar.gz.age`. Validate every SQLite database, then start the restored service on a network-isolated host with matching binaries and a rewritten local storage root. Do not expose restored listeners or publish stale membership. Preserve/reapply all newer deletion receipts, revoked-device records and account-erasure requests before returning restored state to service.

For **newly provisioned Spaces**, set `recovery_recipient` in the hosting configuration to the same age public recipient. The host writes `spaces/<id>/service-recovery.age` before advertising the Space. The backup includes this encrypted service recovery card. Existing service root secrets that were discarded cannot be reconstructed; complete device-vault backups preserve their current controller instead.

The host shares four SQLite worker slots across profiles. A corrupt Space stays unavailable and consumes its allocation, while healthy Spaces continue serving. Deletion tombstones remain permanent; completed cleanup is recorded so a restart does not contact attachment storage for it. HTTP deletion and subsequent requests return the durable signed receipt without contacting attachment storage or acquiring the creation lock. Access closes immediately; physical cleanup retries only in the background. The defaults admit 128 Spaces, 32 creations per deployment/day and four per IPv4 address or IPv6 /64/day, alongside the two-Space identity limit. These are capacity/abuse budgets, not proof of a unique human. Only interrupted reservations that never issued an invitation expire after 24 hours; inactivity never deletes a published Space.

### Isolate the local attachment bridge

A loopback bind is not authorization between local users. Restrict MEGA's WebDAV port to the hosting service UID, attachment daemon UID and root using an nftables output rule. Cover both `127.0.0.1` and `::1`, persist it with the existing firewall configuration, and verify that a request as `elo-wake` or `elo-call` is rejected while hosting still works. Do not expose or log the private WebDAV collection URL. Bound wake and MEGA service memory and task counts as well as the hosting service. Keep key-only SSH, disable root/password/X11 access after testing a separate key connection, and retain a guarded rollback until that check succeeds.

## Coordinated device-security upgrade

Deploy matching clients, `elo-team` and Replica code when enabling access proofs v2. Old proofs and pairing links are rejected; upgrading only the server interrupts old clients. The hosted service derives its trusted public origin from `public_url`. For a standalone Replica behind TLS, pass `--public-origin https://your-replica.example` while retaining its loopback bind and `--allow-insecure-loopback`. Forward the original URI unchanged; do not derive origin from request headers.

Back up the host root's `revoked-devices/` together with all Space state and Replica databases. The signed device tombstones are permanent and shared across Spaces, including subsequently created ones. Never prune them to free space or restore an older registry while retaining newer app state. A full registry refuses additional entries. The Replica nonce table is durable too; copying or restoring live database files outside the documented SQLite backup process is unsafe.

Before production rollout, verify pairing with independent credentials, interrupted root-code recovery, revoked-device denial after server restart, private-chat recipient updates, and offline host retries. Existing devices that shared one credential must be linked again to receive independent credentials; the server cannot distinguish old copies of the same key. Keep the original controller available until private chats have adopted the new device, or use the explicit controller-recovery process.
