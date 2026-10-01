# Building from source

## Prerequisites

- Rust and Cargo via rustup. `rust-toolchain.toml` pins the toolchain used by this source tree.
- Node.js 24 LTS (recommended, also used by CI) or Node.js 26+ and npm. Keep the supplied `package-lock.json` and `Cargo.lock`.
- The native build dependencies required by Tauri for your platform. On macOS install Xcode and its command-line tools; on Windows use the MSVC toolchain and WebView2; on Linux install the WebKitGTK 4.1 development packages and the other Tauri system dependencies.
- Mobile builds additionally need Xcode with an iOS SDK (macOS only), or an Android SDK/NDK and JDK. Install the appropriate Rust targets for your simulator/device. Xcode 27 iOS builds with `mobile-push` also require rustup's `llvm-tools` component (`rustup component add llvm-tools`) so the build can export the Swift package bridge symbols.

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

The Tauri configuration creates native desktop packages for the current host.
The Desktop release workflow packages macOS (`.dmg` for Apple Silicon and Intel), Windows (x64 NSIS installer) and Linux (x64 `.deb` and AppImage) builds as workflow artifacts. Only successful builds are attached to a release. Distribution signing and notarization still require the publisher's
platform credentials and must stay outside the repository.

The download workflow applies an ad hoc signature to the complete macOS app
bundle and verifies its resource seal before packaging. This is an integrity
check, not Developer ID signing or notarization. A local equivalent is
`npm run tauri -- build --bundles app,dmg --config '{"bundle":{"macOS":{"signingIdentity":"-"}}}'`.
Use the appropriate distribution identity instead when preparing a signed release.

Future runs of the Desktop release workflow stage only final installers, generate
SHA256SUMS, and attest their provenance in a separate job with no build scripts.
To verify a downloaded installer, use `gh attestation verify PATH --repo OWNER/REPO`
with the actual publisher repository, then check its release checksum. This binds
the file to the GitHub workflow and source revision; it does not replace Apple
notarization or Windows Authenticode. Previously published packages have no
retroactive attestation. The workflow must complete successfully before publishing
its resulting installers.

## iOS and Android projects

Native source customizations are retained under `src-tauri/gen`. Machine-specific dependency paths, Xcode projects, SDK paths, generated bindings, compiled libraries and signing files are excluded. Initialize the matching native project using the Tauri CLI and regenerate its platform-specific files on your machine:

```sh
npm run tauri -- ios init
# or
npm run tauri -- android init
```

The Android project uses Gradle 9.8.0, AGP 9.4.1 and Kotlin 2.4.20 with JDK 17
and Android SDK Platform 37.0 (`platforms;android-37.0`).
Use the released API 37 baseline; do not adopt QPR preview SDKs for production builds.
The application target remains API 36; the minimum is API 27 (Android 8.1).
Target API 37 is a separate behavior migration: it changes background audio and
local-network permissions and removes the large-screen orientation opt-out.
Do not raise it solely to hide the `OldTargetApi` suggestion while preserving
the current behavior is a release requirement.
The iOS minimum is 16.0. Audio/video sessions are explicitly joined in a chat.
Android uses an ongoing microphone/camera service; iOS uses an active audio
session. CallKit, PushKit, Android Telecom and full-screen incoming-call
notifications are not used. The existing portrait layout is preserved.
Android-only copies of Tauri modules under [vendor/android](../vendor/android/README.md)
migrate the removed `kotlinOptions.jvmTarget` DSL to `compilerOptions`. Java and
Kotlin target JVM 11 for current AndroidX.
All ten Android modules, including the application, use AGP's built-in Kotlin and public
Android DSL. The root buildscript pins Kotlin 2.4.20; JVM 11 remains explicit.
The local [Wry patch](../vendor/wry/ELO_PATCH.md) updates generated WebView APIs.
Release builds enable both R8 and resource shrinking. Runtime-selected notification icons have explicit resource keep rules. Android 27+
uses adaptive vector launcher icons; PNG store-art sources are not APK resources.
`settings.gradle` normalizes Tauri's generated dependency script before evaluation
to avoid Gradle's deprecated configuration property delegates.

FCM registration uses Firebase Installation IDs on both mobile platforms:
`register`/`unregister`, the registration callback, and HTTP v1 `message.fid`.
The Android manifest and iOS Info.plist explicitly enable installation-ID mode.
Obtaining an FID alone is insufficient: Messaging registration must succeed first.
Update the notification server and mobile builds together; the sender
does not fall back to deprecated FCM registration-token addressing.

Do not restore the deprecated `android.builtInKotlin=false`, `android.newDsl=false`
or `android.nonFinalResIds=false` compatibility settings. Keep Firebase resource generation enabled (`buildFeatures.resValues`)
and apply the generated Tauri script through `file("tauri.build.gradle.kts")` to
avoid the Android Lint Kotlin-script resolver crash. The vendored share plugin
also includes its declared consumer ProGuard file. Keep `settings.gradle` and
the `ExecOperations` build task when regenerating: the settings overrides check their upstream versions against
`Cargo.lock` and stop the build when the copies need review.

The Android TLS verifier shim is versioned from `Cargo.lock`. Its Maven repository
is pinned to a reviewed upstream commit in `app/build.gradle.kts`; update that
commit together with the Rust verifier when a new shim version is needed.

Review the resulting diff before building: retain the checked-in camera/biometry permissions, notification integration, TLS verifier integration, launch resources and native source customizations. The iOS `project.yml` is the source for the Xcode project. Its app target uses `TARGETED_DEVICE_FAMILY: "1"` (iPhone only); preserve this setting when regenerating the Xcode project. Set your own Apple development team locally; use your own identifiers if distributing a fork. Android release signing is supplied separately.

Run `python3 tools/sync_mobile_brand.py` from the repository root after both native projects are initialized to refresh the checked-in application icons. Then, from `apps/desktop`:

```sh
npm run tauri -- ios dev
# or
npm run tauri -- android dev
```

A simulator build is not a device-signed or app-store-ready package. Mobile initialization and signing must be validated on the contributor's toolchain.

### iOS startup and delivery checks

Keep the nonempty `UIApplicationSceneManifest` in both `project.yml` and the
generated `Info.plist`. This app uses one `TaoScene` with `TaoSceneDelegate` and
`UIApplicationSupportsMultipleScenes = false`. iPhone-only targeting does not
remove the scene-lifecycle requirement. The local Tao patch is documented in
[vendor/tao/ELO_PATCH.md](../vendor/tao/ELO_PATCH.md); keep its Cargo override.

Before delivery, check the actual archive **and exported IPA**:

```sh
python3 tools/check_ios_startup.py /path/to/elo.xcarchive
python3 tools/check_ios_startup.py /path/to/elo.ipa
python3 tools/check_ios_privacy.py /path/to/elo.xcarchive --push
```

Launch the release build on iOS/iPadOS 27, including iPhone compatibility mode
on an iPad, before resubmitting the startup-crash rejection. Check cold launch,
background/foreground transitions and cold/warm `elo:` links. Static checks and
an iOS 26 launch are not evidence of successful operation on iOS 27. Preserve
the matching archive/dSYM UUID for each delivered build.

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
| `TAURI_ELO_SPACE_HOST_URL`, `TAURI_ELO_WAKE_URL` | Explicit separate overrides; the host value must include `/spaces/v1/create`, while wake is an HTTPS origin. Cannot be combined with the API-origin setting. `ELO_SPACE_HOST_URL` is the direct Cargo alias. |
| `TAURI_ELO_FIREBASE_IOS` | Absolute path to your Firebase iOS client plist |
| `TAURI_ELO_FIREBASE_ANDROID` | Path to your Firebase Android client JSON |
| `TAURI_ELO_ANDROID_SIGNING` | Absolute path to a private Android signing configuration |
| `TAURI_ELO_TEAM_REPLICA_DESCRIPTOR` | Private descriptor for explicitly enabled `team-test-replica` builds |

The `team-test-replica` feature embeds the selected client access capabilities into the binary; only supply a descriptor explicitly intended for that build's audience. Never supply an administrator's configuration.

A Firebase service-account key belongs only on the wake-service host. APNs keys belong in your notification-provider configuration. Neither belongs in the application, repository or release resources. Do not commit environment files, `.p8`, `.p12`, keystores, provisioning profiles or personal test profiles.

iOS uses the Push Notifications entitlement for ordinary messages and the audio
background mode for an explicitly joined session. CallKit, PushKit and the former
VoIP-token App Attest enrollment are not part of the session model.
See [wake setup](SELF_HOSTING.md#6-firebase-apns-and-the-wake-service).

## Single-VPS setup

See [API compatibility and required updates](API_COMPATIBILITY.md) before changing
server contracts or setting a minimum application version. Release discovery is
additive; cryptographic protocol changes need a separately verified rollout.

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
