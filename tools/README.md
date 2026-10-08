# Project tooling

Run these commands from the repository root. Application build prerequisites and
standard Rust/frontend checks are in [Building](../docs/BUILDING.md).
These scripts provide focused regression checks, asset generation and local
release preparation. They do not upload releases or deploy the website.

## Optional browser tools

Playwright is an optional development dependency of these scripts, not an
application dependency. Install it outside the checkout so the app's package
manifest and lockfile stay unchanged. `pngjs` is needed by the native-media layout
check.

```sh
ELO_QA_TOOLS="$(mktemp -d)"
npm install --prefix "$ELO_QA_TOOLS" --no-save --no-package-lock playwright pngjs
export NODE_PATH="$ELO_QA_TOOLS/node_modules"
"$ELO_QA_TOOLS/node_modules/.bin/playwright" install chromium
export CHROME_PATH="$(node -e 'process.stdout.write(require("playwright").chromium.executablePath())')"
export ELO_QA_CHROME="$CHROME_PATH"
```

These are POSIX-shell commands; Windows users can set the same environment
variables with their shell. Browser downloads may require additional system
packages on Linux. Remove the temporary tools directory when finished.

`check_desktop_ui.mjs` and the landing scripts accept `CHROME_PATH`; their default
is Google Chrome at its usual macOS location. `check_code_input.mjs` uses
`ELO_QA_CHROME` instead. `check_composer_viewport.mjs` accepts `CHROME_PATH`, then
uses macOS Chrome if installed, otherwise Playwright's downloaded Chromium.

The expiry, profile-startup, message-motion and native-media scripts currently
use the macOS Chrome path directly. Their browser execution requires a Mac with
Google Chrome; `CHROME_PATH` does not override those scripts.

## Interface regression checks

Start the development server in one terminal:

```sh
npm --prefix apps/desktop ci --ignore-scripts
npm --prefix apps/desktop run dev
```

In another terminal with the browser-tools environment set:

```sh
node tools/check_desktop_ui.mjs
node tools/check_code_input.mjs
ELO_QA_ORIGIN=http://127.0.0.1:1420 node tools/check_composer_viewport.mjs
```

On macOS with Google Chrome, the remaining checks are:

```sh
node tools/check_expiry_ui.mjs
node tools/check_profile_startup.mjs
node tools/check_message_motion.mjs
node tools/check_native_media.mjs
```

| Tool | Coverage | Local server configuration |
| --- | --- | --- |
| `check_desktop_ui.mjs` | Desktop navigation, responsive layouts, appearance, message actions, settings and mocked IPC wiring. | `DESKTOP_TEST_URL`, default port 1420. Optional `DESKTOP_SCREENSHOTS` directory. |
| `check_code_input.mjs` | Code and QR input presentation across mobile sizes and themes. | `ELO_QA_URL`, default port 1420; optional `ELO_QA_SCREENSHOTS`. |
| `check_composer_viewport.mjs` | Keep taps during a simulated keyboard, temporary blur, subpixel viewport changes, textarea growth/shrinking and stable message geometry. | `ELO_QA_ORIGIN`, default `http://127.0.0.1:1437`; the command above uses Vite's standard port. |
| `check_expiry_ui.mjs` | Expiry controls, composer focus/size and message-list behavior during viewport changes. | Fixed local port 1420; screenshots go to `/private/tmp`. |
| `check_profile_startup.mjs` | Delayed profile loading, login/registration visibility and the injected appearance bridge with mocked native callbacks. | Fixed local port 1420. |
| `check_message_motion.mjs` | Live-message entrance, local echoes, history refresh and reduced-motion behavior. | `ELO_QA_URL`, default port 1420. |
| `check_native_media.mjs` | Native-bridge lifecycle cancellation and call layout using fictional peers and mocked media rendering. | `ELO_QA_URL`, default port 1420; also requires `pngjs`. |

The browser checks use the isolated `apps/desktop/tests/` or
`apps/desktop/marketing/` entries with fictional state and mocked IPC. Keep their
URLs on a local fixture server. They do not open native profiles, contact real
participants or establish real media calls. Browser results do not establish
physical iOS keyboard behavior, Face ID/Keychain presentation, APNs/FCM delivery
or native camera/microphone behavior. Test those paths on the corresponding
native build and device.

## Website generation and review

The checked-in website is static. To regenerate it, create the local publisher
configuration from the public example and fill in the required publisher fields:

```sh
cp landingpage/publisher.example.json landingpage/publisher.json
python3 tools/build_landing.py
python3 tools/check_release_materials.py --landing-only
node tools/review_landing.mjs --landing-only
```

Keep `publisher.json` local. The generator writes product/legal HTML, sitemap,
robots and `apps/desktop/src/locales/legal.en.json` together; review the website
and app-catalog diff. The Python checker validates local page links and
social/discovery metadata. The browser review starts its own loopback server on
port 1438 (`LANDING_REVIEW_PORT` overrides it), checks eight routes at four widths
and saves screenshots/results under `/private/tmp`. Both `--landing-only`
commands work without store-release artwork.

To refresh fictional product captures, keep Vite running and use:

```sh
MARKETING_PREVIEW_URL=http://127.0.0.1:1420/marketing/ node tools/capture_marketing.mjs --landing-only
node tools/render_landing_preview.mjs
python3 tools/check_release_materials.py --landing-only
node tools/review_landing.mjs --landing-only
```

Capture uses the real React interface with fictional team data and writes four
product images under `landingpage/assets/`. Its default fixture port is 1437.
The social-preview renderer uses existing local assets to write a 1200×630 image;
it needs no Vite server. `--landing-only` avoids generating or requiring store
artwork. These checks validate files and layout; they do not verify a deployed
service or complete legal/store review. See the
[website README](../landingpage/README.md) for public runtime files and links.

## Native build and release helpers

`tests/ios_unlock_cover_test.cpp` exercises the production unlock-cover state
machine without launching iOS or opening profiles. Use a C++17 compiler:

```sh
ELO_COVER_BUILD="$(mktemp -d)"
c++ -std=c++17 -Wall -Wextra -pedantic tools/tests/ios_unlock_cover_test.cpp -o "$ELO_COVER_BUILD/unlock-cover-test"
"$ELO_COVER_BUILD/unlock-cover-test"
rm "$ELO_COVER_BUILD/unlock-cover-test"
rmdir "$ELO_COVER_BUILD"
```

| Tool | Purpose and boundaries |
| --- | --- |
| `check_ios_startup.py APP_OR_ARCHIVE_OR_IPA` | Inspects the final scene manifest, single-window declaration, portrait orientation and iPhone target. Also accepts `Info.plist`. Physical cold/warm launch checks remain necessary. |
| `check_ios_privacy.py APP_OR_ARCHIVE [--push]` | Validates embedded manifests in a built `.app` or `.xcarchive`; `--push` includes notification SDK, LiveKit, SwiftProtobuf and native media framework manifests. Complements Xcode's final privacy report. |
| `check_android_jni.py APK_OR_AAB` | Checks actual DEX definitions and static entry points for both WebRTC JNI runtimes after R8. Run on every final release artifact; retained class-name strings alone do not pass. Physical Android call testing remains necessary. |
| `prepare_macos_signing.py --help` | Creates signing configuration in a new private output directory using an explicitly supplied development provisioning profile and installed signing identity. Keep inputs/outputs outside source control. |
| `test_prepare_macos_signing.py` | Tests signing-profile validation with synthetic fixtures: `python3 -m unittest discover -s tools -p 'test_prepare_macos_signing.py'`. |
| `stage_desktop_release.py BUNDLE_DIRECTORY NEW_OUTPUT_DIRECTORY` | Copies final desktop installers and writes SHA-256 checksums. Requires Python 3.11 or newer and a fresh output directory; does not publish. |
| `sync_mobile_brand.py` | Copies approved icons into initialized Android/iOS projects and removes superseded generated Android launcher variants. Review the asset diff before rebuilding. |
| `build_notification_sounds.py` | Regenerates bundled WAV files from supplied recordings and synthesized chimes; requires `ffmpeg`. |
