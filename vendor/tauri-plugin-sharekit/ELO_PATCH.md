# elo.now Android share-file patch

This directory vendors `tauri-plugin-sharekit` 0.3.1 under its MIT license.

On Android, upstream copies a shared file to the root of the app cache. The
app's FileProvider deliberately grants access only to `elo-captures/`; the
upstream copy therefore fails when the plugin requests a content URI. Copy the
file to that existing private directory. Do not broaden FileProvider to the
entire cache, which also contains private exchange and profile data.

The Rust and iOS code is otherwise unchanged from 0.3.1.

The Android build uses Kotlin 2.4's `compilerOptions` and includes the consumer
ProGuard file declared by upstream but missing from its source package. AGP 9
requires that file to exist; Tauri supplies the plugin retention rules.
