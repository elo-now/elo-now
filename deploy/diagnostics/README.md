# Live beta diagnostics

An optional, publisher-operated error receiver for iOS, Android and macOS beta
builds. It complements Firebase Crashlytics: live app errors appear in the admin
panel without restarting the app; native crash reports still use Crashlytics.
The existing **Settings → Debug** switch controls both. Collection is off by
default. This service is independent of Space hosting, membership and storage.

## Data and delivery

Only a generated vocabulary of error codes and operation names is accepted.
Reports contain platform, CPU architecture, app version/build, an independently
random installation ID, a report ID, creation time, error source/code and up to
12 prior diagnostic events with optional elapsed times. The receiver adds its
receipt time. It does not accept free text, stack traces, message contents,
names, credentials, invitation links, payloads or arbitrary extra fields.
IP addresses and HTTP headers are not persisted by this collector. Network
infrastructure still processes IP addresses during transport; configure its
logging separately. Native device details and stack traces remain in Firebase.

The client keeps at most 64 pending reports, expires them after seven days and
retries transient failures while running (2–300 seconds backoff). A TLS 204
acknowledges durable storage; retries use the same report ID. Offline or
suspended devices cannot provide real-time delivery. Turning Debug off cancels
delivery and clears the local queue; an already received report cannot be
recalled. Existing duplicate/rate limits mean this is diagnostic sampling, not
a complete audit trail or a guarantee to capture every displayed error.

Server reports expire after 14 days, with a cleanup pass every minute and a
read-time cutoff. The newest 10,000 reports are retained, subject to a 128 MiB
SQLite limit. Secure deletion and full auto-vacuum reclaim deleted content.
Keep `/srv/elo-diagnostics` out of routine backups; snapshot retention must be
managed separately. These limits do not apply to Firebase retention.

## Access boundaries

- The public proxy exposes only **POST `/diagnostics/v1/errors`**, up to 16 KiB.
- The collector binds to **127.0.0.1:17930**, runs as `elo-diagnostics`, and has
  no access to Docker, profiles, messaging databases or witness keys.
- Reads require a separate local credential. The admin backend reads it from
  `/srv/elo-admin/diagnostics-read-key`; it never enters browser responses.
- **Admin → Logs** inherits the existing VPN restriction and HTTPS Basic auth.
  Filters cover platform, app version, build, error code and installation ID;
  older results use bounded cursor pagination. Newest results refresh every
  ten seconds while visible, except when a report is expanded for inspection.
- Ingestion is anonymous. A secret bundled in a public app would not prove its
  identity. Reports and installation IDs are untrusted diagnostics, never
  authorization or billing evidence. Schema validation, an eight-request
  concurrency limit, request timeouts, global/per-installation rate limits and
  bounded disk storage limit abuse. A hostile sender can still exhaust the
  shared diagnostic budget; chat services are separate.

## Install on an existing native admin/API host

Python 3.10+ with SQLite, systemd and the existing Caddy proxy are required.
Regenerate `codes.json` from the matching application source before packaging:

```sh
python3 deploy/diagnostics/generate_codes.py
python3 -m unittest discover -s deploy/diagnostics -v
python3 -m unittest discover -s deploy/admin -v
```

Copy only `deploy/diagnostics` and `deploy/admin` to the host. Exclude caches
and private files. The installer updates the admin server/static files, adds
one exact ingestion route and restarts the public proxy and admin service.
Plan that brief proxy interruption outside active calls.

```sh
sudo python3 deploy/diagnostics/install.py \
  --proxy-config /srv/elo-api/proxy/config/Caddyfile \
  --proxy-container elo-api-proxy-1 \
  --admin-source deploy/admin
```

The installer retains the changed admin/proxy files in root-only
`/var/lib/elo-diagnostics-deploy`. Review/remove this rollback directory after
acceptance before a later install. The installer restarts the collector after
replacing its code. No service accounts or Firebase billing changes are
needed. Containers remain an optional
hosting path; this receiver is a native systemd service.

Build the app with `beta-diagnostics`, `TAURI_ELO_LIVE_DIAGNOSTICS_URL` set to your
HTTPS ingestion route, and numeric `TAURI_ELO_DIAGNOSTICS_BUILD`. Use the same endpoint
for all tester platforms. Never put a read credential in the app. For an
unconfigured build the live channel is disabled.

Acceptance: with Debug on, use **Queue test report** and verify its actual
platform/build in **Logs** without restarting. Verify a retry creates one row,
malformed reports return 400, unauthenticated admin reads fail, the public
origin does not expose `/reports` or admin log data, and Debug off clears
pending client reports. Fatal crashes require separate Crashlytics validation.
