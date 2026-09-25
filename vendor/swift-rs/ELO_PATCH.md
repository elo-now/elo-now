# Local build integration

This copy retains the upstream license. elo's build bridge handles Xcode 27
cross-compilation with an explicit Swift target triple, clamps the iOS deployment
target to the supported minimum, locates the actual output archive, and preserves
the C bridge symbols required by Rust/Tauri.

Nested SwiftPM compilation honors Cargo's worker count, capped at two, so a
bounded Cargo build cannot silently start a host-wide parallel Swift build.
Dependency resolution disables Keychain and netrc lookup: this application's
Swift packages use public sources and need no publisher account credentials.
Certificate validation, package fingerprints and signing checks are unchanged.
