# Building from source

## Prerequisites

- Rust and Cargo via rustup. `rust-toolchain.toml` pins the toolchain used by this source tree.
- Node.js 22 or later and npm. Keep the supplied `package-lock.json` and `Cargo.lock`.
- The native build dependencies required by Tauri for your platform. On macOS install Xcode and its command-line tools; on Windows use the MSVC toolchain and WebView2; on Linux install the WebKitGTK 4.1 development packages and the other Tauri system dependencies.
- Mobile builds additionally need Xcode with an iOS SDK (macOS only), or an Android SDK/NDK and JDK. Install the appropriate Rust targets for your simulator/device.

Install frontend dependencies from `apps/desktop`:

```sh
npm ci
```

## Desktop development

From `apps/desktop`:

```sh
npm run tauri -- dev
```

The normal source build does not embed access to the publisher's Demo services. No production credentials are required to compile it. A configured remote Space requires its operator's invitation and infrastructure.

For a local release binary:

```sh
npm run tauri -- build
```

Installer bundling and platform signing must be configured for your own distribution. The included configuration does not enable installer bundling by default.

## iOS and Android projects

Native source customizations are retained under `src-tauri/gen`. Machine-specific dependency paths, Xcode projects, SDK paths, generated bindings, compiled libraries and signing files are excluded. Initialize the matching native project using the Tauri CLI and regenerate its platform-specific files on your machine:

```sh
npm run tauri -- ios init
# or
npm run tauri -- android init
```

Review the resulting diff before building: retain the checked-in camera/biometry permissions, notification integration, TLS verifier integration, launch resources and native source customizations. The iOS `project.yml` is the source for the Xcode project. Set your own Apple development team locally; use your own identifiers if distributing a fork. Android release signing is supplied separately.

Run `python3 tools/sync_mobile_brand.py` from the repository root after both native projects are initialized to refresh the checked-in application icons. Then, from `apps/desktop`:

```sh
npm run tauri -- ios dev
# or
npm run tauri -- android dev
```

A simulator build is not a device-signed or app-store-ready package. The initial source export has been checked for desktop/frontend build completeness; mobile initialization and signing must be validated on the contributor's toolchain.

## Optional services and mobile push

The workspace also builds the service executables:

```sh
cargo build --locked -p elo-cli -p elo-team -p elo-wake
cargo run --locked -p elo-cli -- --help
```

Provision your own Replica, Space enrollment service and optional wake service. Live service configuration, infrastructure addresses and private access capabilities are deliberately not supplied in this repository. Use HTTPS and keep private configuration outside the checkout.

The optional Tauri `mobile-push` feature enables the native push plugin. Its build integration accepts these environment variables:

| Variable | Purpose |
| --- | --- |
| `TAURI_ELO_WAKE_URL` | HTTPS URL of your wake service |
| `TAURI_ELO_FIREBASE_IOS` | Absolute path to your Firebase iOS client plist |
| `TAURI_ELO_FIREBASE_ANDROID` | Path to your Firebase Android client JSON |
| `TAURI_ELO_ANDROID_SIGNING` | Absolute path to a private Android signing configuration |
| `TAURI_ELO_TEAM_REPLICA_DESCRIPTOR` | Private descriptor for explicitly enabled `team-test-replica` builds |

The `team-test-replica` feature embeds the selected client access capabilities into the binary; only supply a descriptor explicitly intended for that build's audience. Never supply an administrator's configuration.

A Firebase service-account key belongs only on the wake-service host. APNs keys belong in your notification-provider configuration. Neither belongs in the application, repository or release resources. Do not commit environment files, `.p8`, `.p12`, keystores, provisioning profiles or personal test profiles.

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
