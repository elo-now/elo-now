# Local biometric adapter patch

Based on tauri-plugin-biometry 0.3.0-rc.3. iOS Keychain storage uses
`biometryCurrentSet` and `WhenUnlockedThisDeviceOnly`, so enrolling new biometrics
invalidates the stored wrapping key. Android already uses an authentication-bound
Keystore private key, enrollment invalidation, AES-GCM bound to domain/name and
`BiometricPrompt.CryptoObject` for decryption.

elo stores only a random age wrapping key through this adapter. The profile
password is wrapped in a separate local file, excluded from portable exports.
Old password entries require explicit reenrollment. Preserve upstream licenses.

The macOS bridge is enabled for elo and uses the data-protection Keychain on
every item operation. Its device-local entries use `BiometryCurrentSet`, matching
iOS; a Mac account password cannot replace the biometric check. Each read uses
a fresh authentication context with no Touch ID reuse and releases the copied
Core Foundation data. Reads and writes run outside the async worker pool because
Keychain may wait for authentication. The bridge reports `keychainUnavailable`
when the app signature lacks access to the protected Keychain, so the UI does not
offer enrollment in an ad hoc build. Mobile and macOS use different native
biometric enums; the frontend adapter selects the mapping from native platform
metadata.

The Android non-crypto prompt and availability check use explicit AndroidX
`BIOMETRIC_WEAK` authenticators on every supported OS. Optional device-credential
fallback remains controlled by the existing flag and secure-lock check. These
replace deprecated convenience APIs without changing the accepted authenticator
set or the separate Keystore `CryptoObject` flow. The module uses AGP's built-in
Kotlin with JVM 11.
