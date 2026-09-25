# Android build compatibility patches

These Android modules are copied from the corresponding published crates. Original
licenses are preserved. Rust and iOS continue using the upstream crates from Cargo.
`kotlinOptions.jvmTarget` is migrated to `kotlin.compilerOptions.jvmTarget`;
Java/Kotlin bytecode targets are aligned at JVM 11, as required by current AndroidX. AndroidX, Material, Jackson 2.x,
CameraX and ML Kit dependencies are refreshed; the modules use the application
minimum API 24 and compile API 37.0. No native runtime code is changed.

`apps/desktop/src-tauri/gen/android/settings.gradle` selects these modules after
Tauri generates its module list. It checks these versions against `Cargo.lock`
and fails configuration if a crate update has not been reviewed here.
Remove each override once its upstream Gradle script supports Kotlin 2.4. Do not
copy generated Gradle caches or build products into this directory.

| Crate | Version | Source crate SHA-256 |
| --- | --- | --- |
| `tauri` | 2.11.6 | `6fa5bacdb9bbad5954af3d1bd6cf6ae9192cab1b2e270f4a07f904610b9e85f4` |
| `tauri-plugin-barcode-scanner` | 2.4.6 | `81f76741c77b8213350fd37a5608f0c78f4e61fe33f0334f5dfd0e6cc8d00138` |
| `tauri-plugin-deep-link` | 2.4.10 | `92d489b8ecceae1cd09f6e1f7606f2095ac721cc8d54cf2f0e6bb377cc52cff6` |
| `tauri-plugin-dialog` | 2.7.3 | `61854a36651aa48381e5e209f69a01273b77f3f9f91f0c430b1b98d33bd47229` |
| `tauri-plugin-fs` | 2.5.2 | `de22eef34fd78c0da050e748710edd50bf127e651d02ea1b2bfada1523cc5c51` |
