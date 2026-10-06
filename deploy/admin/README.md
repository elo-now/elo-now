# Hosting administration

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
- for an API listening on port 19900, `--api-port 19900` (default: 18900).

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

## Use

1. Open `https://<api-host>/admin/` and sign in.
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
requires HTTPS Basic authentication and supplies a private proxy credential.
Writes additionally require an exact Origin and a CSRF token. The server bounds
request size, concurrency and the number of pending configuration jobs.

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
