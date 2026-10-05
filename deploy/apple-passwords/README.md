# macOS Keychain and Password AutoFill preparation

The local macOS development build needs an Apple-authorized app identity for
the Data Protection Keychain used by optional Touch ID. The default ad hoc
desktop bundle intentionally has no restricted signing entitlements. Adding
entitlement names to an ad hoc signature does not authorize them.

## Local test signing

In [Apple Developer](https://developer.apple.com/account/resources/profiles/list),
create **Mac App Development** for the explicit `now.elo` App ID in team
`F3HJA47BQU`, select an existing Apple Development certificate with its private
key on the build Mac, and include the test Mac. If the Mac is not registered,
use the Provisioning UDID shown in System Information. Enable Associated Domains
on the App ID and regenerate the profile only if also testing `webcredentials`.
No new distribution certificate is needed for this registered-Mac test.

Save the downloaded `.provisionprofile` under a private local directory. From
the repository root, use the SHA-1 reported by `security find-identity -v -p
codesigning` for the selected Apple Development certificate:

```sh
python3 tools/prepare_macos_signing.py \
  --profile /absolute/private/path/elo-macos-development.provisionprofile \
  --identity CERTIFICATE_SHA1 \
  --output .private/macos-signing
```

Add `--webcredentials` only with a profile authorizing Associated Domains.
The tool checks platform, exact app/team, expiry, registered Mac, available
signing identity, profile certificate and requested entitlements. It writes
private files with mode `0600` in a new `0700` directory. The overlay embeds the
unchanged profile at `Contents/embedded.provisionprofile`, enables hardened
runtime and grants only elo.now's own Keychain group. It does not add debugger
access or export any private key. Apple/macOS still validate the profile and
final signature; these local checks do not replace that validation.

From `apps/desktop`, build with the generated overlay after the normal build
environment and public service pins are configured:

```sh
npm run tauri -- build --bundles app \
  --config ../../.private/macos-signing/tauri.macos-development.conf.json
```

Unset `APPLE_SIGNING_IDENTITY` if an earlier ad hoc build set it to `-`; it must
not override the profile-bound identity. Inspect the final app before testing:

```sh
codesign --verify --deep --strict --verbose=2 /absolute/path/elo.now.app
codesign -d --entitlements :- /absolute/path/elo.now.app
```

Confirm the application identifier, team identifier, exact Keychain group and
embedded profile. Run a separate disposable elo.now profile, explicitly enable
Touch ID after unlocking with its password, lock the app, and verify success,
cancel and restart using the real Touch ID prompt. A development signature is
for the registered test Mac; it is not a notarized public installer or a store
submission. Developer ID distribution needs its own certificate and profile.

## Associated domain artifact and limits

`apple-app-site-association` contains the proposed public `webcredentials`
section for `F3HJA47BQU.now.elo`. It is **not deployed** by this tool. Merge this
section into the existing file before approved deployment to
`https://elo.now/.well-known/apple-app-site-association`; preserve existing
`applinks` and other services. Serve JSON directly over HTTPS without redirects.
Apple's associated-domain CDN may delay visibility after a change.

The app's optional entitlement is exactly `webcredentials:elo.now`. This is
necessary domain authorization, not proof of Password AutoFill working inside
the current `tauri://localhost` WKWebView. The login already declares HTML
`current-password`/`new-password`; it uses local profiles, not a website account.
No synthetic username, hidden credential form, remote login page, automatic
password saving or new account is introduced. Native credential integration
and real signed-app behavior still require separate validation before claiming
Apple Passwords support. Touch ID and Password AutoFill are separate features.

Official references:

- [Create a development provisioning profile](https://developer.apple.com/help/account/provisioning-profiles/create-a-development-provisioning-profile)
- [TN3125: Provisioning Profiles](https://developer.apple.com/documentation/technotes/tn3125-inside-code-signing-provisioning-profiles)
- [Keychain access groups](https://developer.apple.com/documentation/security/sharing-access-to-keychain-items-among-a-collection-of-apps)
- [Accessing Keychain items with Face ID or Touch ID](https://developer.apple.com/documentation/localauthentication/accessing-keychain-items-with-face-id-or-touch-id)
- [Supporting Associated Domains](https://developer.apple.com/documentation/xcode/supporting-associated-domains)
- [Password AutoFill on HTML inputs](https://developer.apple.com/documentation/security/enabling-password-autofill-on-an-html-input-element)
