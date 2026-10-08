# Hosting administration

Optional [live beta diagnostics](../diagnostics/README.md) add a **Logs** tab to
this panel. It uses the same VPN and login protection; no log-reading endpoint
is exposed publicly. The tab is shown only when a local diagnostics reader is
configured.

This optional administration service configures an initialized elo deployment.
The API panel edits the hosting name, available message lifetimes, default
lifetime, Space creator allowlist and managed attachment provider. It publishes
an updated signed QR code after saving. Spaces and their owner keys are created
in the app, not in this panel.

The separate storage panel on the witness host saves the managed MEGA or S3
connection and its allowed owner identities. Storage credentials are never
included in a hosting link or returned by the configuration API. Leaving both
credential fields blank preserves a saved connection for the same provider.
Changing provider requires new credentials; it does not migrate existing files.

Managed credentials are copied into an encrypted, versioned configuration when
a Space owner configures managed attachments. Changing the panel's connection
affects subsequent configurations; existing Spaces continue uploading to their
previous folder until their owner reconfigures them. Existing attachments retain
their storage revision for downloads and expiry cleanup. Saving this panel does
not delete those files. Keep the old folder and access available while those
Spaces or attachments still use it.

## Install

First initialize the two hosts with the [container deployment](../containers/README.md).
Python 3, systemd and the already loaded Caddy image are required. Copy this
administration directory, excluding Python caches and tests, to each host. Run
`install.py` as root on each host with:

- `--role api` or `--role witness`;
- `--origin https://<this-host>` and `--related-origin https://<other-host>`;
- `--state /srv/elo-api` or `/srv/elo-witness`;
- `--bundle /opt/elo-containers-<version>`;
- `--version <locally-built-image-version>`;
- `--vpn-client-ip <client-private-ipv4>` (required, also on reinstall);
- optionally `--vpn-client-ipv6 <client-ula-ipv6>` for a dual-stack VPN;
- for an API listening on port 19900, `--api-port 19900` (default: 18900).

Configure the VPN first. These are the client's tunnel addresses, not the hosts'
public addresses. Only one RFC 1918 IPv4 host and, optionally, one ULA IPv6 host
are accepted: for example, `10.77.36.10` and `fd77:36:9b17::10`. Explicit `/32`
and `/128` suffixes are accepted; networks, address lists and public addresses
are rejected. The installer has no fallback that exposes the panel publicly.

Feed a private JSON file to standard input with `password` (24–128 URL-safe
characters) and `proxy_key` (32–256 URL-safe characters). Generate independent
random values for each host. Keep the password in your password manager;
do not put either value in shell arguments or source control. The HTTPS
username is `admin`. Re-running the installer with new values rotates access.

The installer adds `/admin/` to the existing HTTPS proxy and validates its
configuration before restarting **only the proxy**. It does not restart the
witness, initialize a journal, rotate service keys or change the hosting policy.
On proxy failure it restores the previous proxy configuration. Existing SSH,
SFTP and application data remain outside the installer.

## WireGuard setup

On each initialized Debian host, install Debian's `wireguard-tools` package.
Keep `vpn.py`, `apply.py` and `schema.py` in a permanent root-owned directory,
such as `/opt/elo-admin`, with no group or other write permission on the files
or their parent directories. Do not run the provisioner from a temporary upload
directory: its absolute path is used by the service's `ExecStartPre` firewall
check on every start, including after reboot.

Create the client's key pair in the official WireGuard app on the Mac. Its
private key stays on the client; never copy it to either VPS. Each server
generates and retains its own independent private key. Generate a separate
pre-shared key for each server/client pair. On each host, prepare a root-only
JSON file (mode `0600`) containing that server's pair:

```json
{"public_key":"<client-public-key>","preshared_key":"<pair-specific-base64-key>"}
```

Use distinct server tunnel addresses and the same client addresses on both
servers, for example:

| Role | Server IPv4 | Server IPv6 | Client IPv4 / IPv6 |
| --- | --- | --- | --- |
| API | `10.77.36.1` | `fd77:36:9b17::1` | `10.77.36.10` / `fd77:36:9b17::10` |
| Witness | `10.77.36.2` | `fd77:36:9b17::2` | `10.77.36.10` / `fd77:36:9b17::10` |

Run as root on the API host, then repeat on witness with its `.2` / `::2`
server addresses and its own JSON file:

```sh
python3 /opt/elo-admin/vpn.py \
  --server-ip 10.77.36.1 --server-ipv6 fd77:36:9b17::1 \
  --client-ip 10.77.36.10 --client-ipv6 fd77:36:9b17::10 \
  < /root/elo-admin-peer.json
```

The provisioner opens UDP 51820, installs persistent source-address protection
and enables `wg-quick@wg-elo-admin`. It returns the server's public key and
addresses. It expects the container deployment's managed nftables configuration;
it does not replace the existing firewall or enable forwarding.

In the Mac app, use one tunnel with two peers, each with its own server public
key, pre-shared key and public endpoint on port 51820. For each peer, `AllowedIPs`
must contain that server's public IPv4 `/32`, public IPv6 `/128`, private IPv4
`/32` and private IPv6 `/128`. Set the client's interface addresses to
`10.77.36.10/32, fd77:36:9b17::10/128`. Leave DNS unset and add no default route.
All traffic from the Mac to these two VPS addresses goes through the tunnel,
not only HTTP requests to `/admin`. Other destinations use the usual connection.
The official Apple client keeps its own tunnel transport outside those routes.

To revoke a device, remove its public-key peer from the live WireGuard interface
on **both** servers and from both persistent `/etc/wireguard/wg-elo-admin.conf`
files. Remove its entries from retained provisioning inputs as well, so a reboot
or reinstall cannot restore access. Verify that the peer is absent on both hosts;
do not print complete WireGuard configurations or private keys for diagnostics.

## Use

1. Connect the configured VPN, open `https://<api-host>/admin/` and sign in.
2. Set the name and retention choices. For private creation, enter the allowed
   public profile identity IDs, one per line.
3. If offering managed attachments, first configure them in
   `https://<witness-host>/admin/`, including allowed owner identities. Then select
   the same provider in the API panel. Public hosting uses owner-supplied storage.
4. Save. After the change succeeds, scan the QR in **Create Space → Add hosting**.
   Review and confirm its configuration, then create the Space in the app.

The hosting catalog is local to each device. A changed profile needs to be
imported again on those devices; it retains its signing key and increases its
revision. Clients reject changed pinned keys and older revisions. Policy changes
apply to newly created Spaces; they do not rewrite the lifetime of existing ones.
A hosting sharing the app's built-in public creation address cannot be imported
as an additional private hosting. A separate private deployment needs its own
canonical creation address.

## Security and recovery

The web process runs as `elo-admin` (UID 21010), listens only on
`127.0.0.1:17910`, and has no access to Docker or service configuration. Caddy
allows `/admin` and every `/admin/*` path only from the configured client's exact
VPN addresses. It uses the direct socket address (`remote_ip`), never forwarded
headers. All other sources receive 404 before any redirect, password prompt or
backend request. Public hosting profiles and application endpoints remain
available through their existing routes.

Inside the VPN, Caddy also requires HTTPS Basic authentication and supplies a
private proxy credential. VPN access does not replace the panel password.
The panel still uses Basic Auth without application sessions or MFA; a VPN is
an additional network access restriction, not a passkey or an MFA implementation.
Writes additionally require an exact Origin and a CSRF token. The server bounds
request size, concurrency and the number of pending configuration jobs.

The setup above keeps the existing HTTPS hostnames and certificates without
changing DNS. Include both address families when the hostname has A and AAAA
records, and give the panel installer the corresponding client tunnel addresses.
Other VPN clients need an equivalent working transport route. The server's
address check remains independent of the client's routing setup and denies
access when the tunnel source does not match.

A fixed root worker independently validates queued data and can update only the
hosting policy or managed storage fields. It cannot change service endpoints,
trust pins, the witness journal or user messages. API edits restart the API;
storage edits restart the storage broker. Neither operation restarts the witness.
A private transaction journal restores the prior configuration if applying a
change fails, including recovery after an interrupted worker. Failed jobs return
a fixed error message, not provider output or credentials.

Configuration jobs may contain storage credentials until applied. Their queue is
private and they are removed on completion. Status files contain no configuration
or secrets and are cleaned after 24 hours. The root-only transaction journal may
contain the previous credentials until commit or rollback completes.

Check `systemctl status elo-admin elo-admin-apply` for failures. To disable panel
access, remove the marked `ELO ADMIN` block from Caddy's configuration, validate
and restart the proxy, then stop and disable `elo-admin.service`,
`elo-admin-apply.path` and `elo-admin-apply.timer`. Disabling the panel does not
remove the hosting or storage configuration.

Run its tests with:

```sh
python3 -m unittest discover -s deploy/admin -v
```

## Temporary private hosting beside the public host

`test_host.py` prepares a separate `elo-api-test` Compose project in
`/srv/elo-api-test` on an existing API host. It is intended for temporary tests,
not isolation from a compromised VPS. It uses the existing hostname on HTTPS
port **9443**, API/control ports **19900/19901**, wake **8878** and calls **19920**.
Only 9443 needs an additional inbound firewall rule; backend listeners stay on
loopback. The original public deployment stays on port 443.

Run as root with `--container-bundle /opt/elo-containers-<version>` and
`--version <version>`. The script creates files only. Review them, export the
signed profile with the copied `export.py`, then start the generated Compose
project explicitly. Install the API panel with both `--state` and `--bundle`
pointing to `/srv/elo-api-test`, `--api-port 19900`, and the `:9443` origin.
Supply the required `--vpn-client-ip` and any configured `--vpn-client-ipv6` here
as well; a separate HTTPS port does not bypass the VPN requirement.
The initial creator allowlist is empty: add the intended public profile IDs
before trying to create a Space.

The test instance has separate API, notification and call-control databases,
export signing keys and admission keys. It shares the existing independent
witness/storage broker and media/TURN services. Its proxy reads the public
host's TLS certificate through a read-only mount; it does not bind ports 80/443
or request its own certificate. Restart the test proxy after the main certificate
renews. Both environments still share the host, Docker daemon, provider account
and capacity.

To remove the test instance, first delete its test Spaces through their owners'
apps, then stop **only** the `elo-api-test` Compose project and disable the API
administration units. Remove the dedicated 9443 firewall rule and this instance's
state after checking that it contains nothing to retain. Preserve the public
API, shared witness/storage, media/TURN, TLS certificate directory and SFTP.
The witness administration panel can remain available for storage management.
