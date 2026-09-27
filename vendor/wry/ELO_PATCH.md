# Android API updates for elo.now

Based on the published Wry 0.55.1 crate, SHA-256
`186f9871daa55fd9c016578b810d149de58367113db7fb72b462d2323ce19514`.
Original licenses are preserved. Cargo selects this copy
through `[patch.crates-io]`, so Android bindings are regenerated from these sources.
Do not patch Cargo's registry cache or only edit the generated Kotlin files.

- Remove WebSQL's deprecated `databaseEnabled` setting. elo.now uses its encrypted
  Rust database and WebView DOM storage; it does not use WebSQL.
- Dispatch back navigation through `OnBackPressedDispatcher`, disabling the
  callback in a `try/finally` block to prevent recursion.
- Use `WebView.getCurrentWebViewPackage()` directly. The application now requires
  Android API 27; the pre-Android-8 package-name guesses are unnecessary.
- Forward `onTrimMemory` notifications to the existing native memory-pressure
  callback instead of overriding the obsolete `onLowMemory` callback.
- Handle renderer termination through `WebViewClient.onRenderProcessGone`:
  detach and destroy the dead view, release its JNI reference, and recreate it
  from the original trusted URL, scripts and native callbacks. Keep the Activity
  and native process alive. Recovery waits for the foreground and stops after
  two attempts within 30 seconds rather than looping on a broken startup.
- The two new JNI callbacks in `binding.rs` and `main_pipe.rs` preserve Wry's
  attributes and IPC handlers while replacing only the terminated WebView.
  The application and vendored Tauri plugins release document-specific references
  and reload their bindings. A renderer crash loses its JavaScript state and
  unsaved input; this patch cannot restore content that was never saved.
- AndroidX WebKit 1.17.1 incorrectly reports Kotlin's super-constructor call as
  constructing an unhandled plain client. Only that constructor is annotated;
  the class-level missing-handler check remains enabled. Remove the workaround
  when upstream's detector excludes super-constructor calls.
- Complete abandoned JavaScript evaluations once and remove their native callbacks
  after delivery, outside the callback-map lock.
- Provide the layout editor constructor without allowing uninitialized runtime
  construction. Format console line numbers with `Locale.ROOT`; retain ASCII
  prompt trimming, including control characters, without the Java-conversion lambda.
- Preserve both photo and video capture for mixed HTML accept types. Android's
  system chooser exposes the matching camera activities; photo-only inputs stay
  photo-only. Grant access to the full-resolution photo output URI, return the
  captured video URI when appropriate, and remove unused photo files on cancellation.
  The app manifest declares both camera intent queries for package visibility.

These changes do not alter the application's layout, WebView history policy or
stored data. Re-evaluate this patch when updating Wry and remove individual
changes when upstream provides them.

Renderer recovery policy tests are in the Android application's unit-test source
set. Run Kotlin tests/Lint and cross-check Wry for `aarch64-linux-android` after
editing this patch. A type-check alone does not demonstrate recovery on a device.
