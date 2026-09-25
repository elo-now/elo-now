# Local biometric adapter patch

Based on tauri-plugin-biometry 0.3.0-rc.3. iOS Keychain storage uses
`biometryCurrentSet` and `WhenUnlockedThisDeviceOnly`, so enrolling new biometrics
invalidates the stored wrapping key. Android already uses an authentication-bound
Keystore private key, enrollment invalidation, AES-GCM bound to domain/name and
`BiometricPrompt.CryptoObject` for decryption.

elo stores only a random age wrapping key through this adapter. The profile
password is wrapped in a separate local file, excluded from portable exports.
Old password entries require explicit reenrollment. Preserve upstream licenses.
