# Building from source

## Prerequisites

- Rust and Cargo via rustup. `rust-toolchain.toml` pins the toolchain used by this source tree.
- Node.js 22 or later and npm. Keep the supplied `package-lock.json` and `Cargo.lock`.
- The native build dependencies required by Tauri for your platform. On macOS install Xcode and its command-line tools; on Windows use the MSVC toolchain and WebView2; on Linux install the WebKitGTK 4.1 development packages and the other Tauri system dependencies.
- Mobile builds additionally need Xcode with an iOS SDK (macOS only), or an Android SDK/NDK and JDK. Install the appropriate Rust targets for your simulator/device. Xcode 27 iOS builds with `mobile-push` also require rustup's `llvm-tools` component (`rustup component add llvm-tools`) so the build can export the Swift package bridge symbols.

Install frontend dependencies from `apps/desktop`:

```sh
npm ci
```

## Desktop development

Before upgrading a running service, read [API compatibility and application updates](API_COMPATIBILITY.md). It distinguishes published 1.0.0 behavior from mechanisms being prepared for the next release; do not assume that a newer server build supports every older client.

From `apps/desktop`:

```sh
npm run tauri -- dev
```

The normal source build does not embed access to the publisher's Demo services. No production credentials are required to compile it. A configured remote Space requires its operator's invitation and infrastructure.

For a local release binary:

```sh
npm run tauri -- build
```

The Tauri configuration creates native desktop packages for the current host.
The Desktop release workflow packages macOS (`.dmg` for Apple Silicon and Intel), Windows (x64 NSIS installer) and Linux (x64 `.deb` and AppImage) builds as workflow artifacts. Only successful builds are attached to a release. Distribution signing and notarization still require the publisher's
platform credentials and must stay outside the repository.

## iOS and Android projects

Native source customizations are retained under `src-tauri/gen`. Machine-specific dependency paths, Xcode projects, SDK paths, generated bindings, compiled libraries and signing files are excluded. Initialize the matching native project using the Tauri CLI and regenerate its platform-specific files on your machine:

```sh
npm run tauri -- ios init
# or
npm run tauri -- android init
```

Review the resulting diff before building: retain the checked-in camera/biometry permissions, notification integration, TLS verifier integration, launch resources and native source customizations. The iOS `project.yml` is the source for the Xcode project. Its app target uses `TARGETED_DEVICE_FAMILY: "1"` (iPhone only); preserve this setting when regenerating the Xcode project. Set your own Apple development team locally; use your own identifiers if distributing a fork. Android release signing is supplied separately.

Run `python3 tools/sync_mobile_brand.py` from the repository root after both native projects are initialized to refresh the checked-in application icons. Then, from `apps/desktop`:

```sh
npm run tauri -- ios dev
# or
npm run tauri -- android dev
```

A simulator build is not a device-signed or app-store-ready package. Mobile initialization and signing must be validated on the contributor's toolchain.

## Optional services and mobile push

The workspace also builds the service executables:

```sh
cargo build --locked -p elo-cli -p elo-team -p elo-wake -p elo-call-service
cargo run --locked -p elo-cli -- --help
```

Provision your own Replica, Space enrollment service and optional wake service. Live service configuration, infrastructure addresses and private access capabilities are deliberately not supplied in this repository. Use HTTPS and keep private configuration outside the checkout.

Set `TAURI_ELO_API_URL` when building a private mobile application, for example `https://chat.example.test`. One HTTPS origin supplies hosted creation at `/spaces/v1/create` and the optional wake service. An explicit private origin has no fallback to the official service. Without an override this source tree builds the official client for `https://api.elo.now`; DNS and services must be provisioned before that client is distributed.

New hosted Replica descriptors use a stable `/spaces/{reservationId}/replica/` base under the service origin. Clients retain the complete path and signing-key pin; changing the physical backend must preserve that logical identity. Existing standalone root Replica descriptors remain readable. No unsigned discovery document or automatic trust-key replacement is used. If both a plain Cargo name and its `TAURI_` alias are set, they must match; conflicting values stop the build. Use the `TAURI_` names with the mobile CLI, which filters variables forwarded to Xcode/Gradle.

The optional Tauri `mobile-push` feature enables the native push plugin. Its build integration accepts these environment variables:

| Variable | Purpose |
| --- | --- |
| `TAURI_ELO_API_URL` | Single HTTPS origin; forwarded by Tauri to Xcode/Gradle. Plain `ELO_API_URL` also works with direct Cargo builds. |
| `TAURI_ELO_SPACE_HOST_URL`, `TAURI_ELO_WAKE_URL` | Explicit separate hosting/wake overrides for QA; cannot be combined with the API-origin setting. `ELO_SPACE_HOST_URL` is the direct Cargo alias. |
| `TAURI_ELO_FIREBASE_IOS` | Absolute path to your Firebase iOS client plist |
| `TAURI_ELO_FIREBASE_ANDROID` | Path to your Firebase Android client JSON |
| `TAURI_ELO_ANDROID_SIGNING` | Absolute path to a private Android signing configuration |
| `TAURI_ELO_TEAM_REPLICA_DESCRIPTOR` | Private descriptor for explicitly enabled `team-test-replica` builds |

The `team-test-replica` feature embeds the selected client access capabilities into the binary; only supply a descriptor explicitly intended for that build's audience. Never supply an administrator's configuration.

A Firebase service-account key belongs only on the wake-service host. APNs keys belong in your notification-provider configuration. Neither belongs in the application, repository or release resources. Do not commit environment files, `.p8`, `.p12`, keystores, provisioning profiles or personal test profiles.

## Single-VPS setup

For a fresh installation on Debian 13 or Oracle Linux 10, follow the [complete self-hosting guide](SELF_HOSTING.md). It identifies each service, private configuration file, public endpoint, storage choice, TLS route and acceptance check. The publisher's credentials and infrastructure are not included.

## Checks

From `apps/desktop`:

```sh
npm run build
npm test
```

From the repository root, after building the frontend:

```sh
cargo check --workspace --locked
cargo test --workspace --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
```

Tests use synthetic identities and deterministic protocol fixtures. Preserve the original bytes of signed fixtures. Native push delivery, OS permissions, device linking and platform signing also require the appropriate real-device checks; passing unit tests alone does not validate those flows.
