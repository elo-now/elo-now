# elo.now native file exchange patches

This directory vendors `tauri-plugin-sharekit` 0.3.1 under its MIT license.

On Android, upstream copies a shared file to the root of the app cache. The
app's FileProvider deliberately grants access only to `elo-captures/`; the
upstream copy therefore fails when the plugin requests a content URI. Copy the
file to a unique subdirectory there so identically named files cannot overwrite
an active share. Explicitly shared copies older than one day are cleaned on
plugin load and before another share; they must survive the chooser callback
because a receiving app may still be reading them. Camera files are untouched.
Do not broaden FileProvider to the entire cache, which also contains private
exchange and profile data.

On iOS, a native-only `export_file` method exports an existing, capability-checked
file through `UIDocumentPickerViewController(forExporting:asCopy:)`. The generic
dialog adapter exports an empty placeholder and collapses plugin errors into
cancellation; this path instead separates setup/presentation failures from the
user cancelling. The complete file is staged under its requested filename in a
private temporary directory, retained until completion, then removed. No new
renderer command or filesystem permission is exposed. File sharing uses the
caller's private temporary file directly, retained until the activity completes,
instead of leaving an extra plaintext copy in the app's temporary root. Both
paths reject unavailable presenters instead of silently waiting forever. The
existing QR sharing interface is unchanged. The package minimum is iOS 16,
matching the application.

The Android build uses Kotlin 2.4's `compilerOptions` and includes the consumer
ProGuard file declared by upstream but missing from its source package. AGP 9
requires that file to exist; Tauri supplies the plugin retention rules.
