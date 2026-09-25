# iOS scene lifecycle patch

Upstream source: tao 0.35.3 (crates.io checksum in the original lockfile:
`d1c93047acf68669466a34690ac58cca7010bd1b201e1ec86f1fd0a75d3dd4a9`).
Only `src/platform_impl/ios/{scene,view,app_state}.rs` differ from that release.

- Use presence of `UIApplicationSceneManifest` for scene lifecycle startup,
  delegate registration and window assignment. Keep the system's
  `supportsMultipleScenes` check for actual additional windows. elo remains a
  single-window, iPhone-targeted application.
- Backport the autorelease ownership fix in
  [tao PR 1245](https://github.com/tauri-apps/tao/pull/1245) to prevent a release-only
  use-after-free of `UISceneConfiguration`.
- Dispatch cold-start URL contexts and user activities after scene connection,
  through the same handlers as warm opens. Treat nil connection-option
  collections as absent: UIKit 27 can return nil on a plain launch despite
  earlier SDK nonnull annotations. Invalid URLs do not panic.

The app declares a nonempty static scene configuration for `TaoSceneDelegate`
(in both Info.plist and the XcodeGen source). This addresses the iOS 27 startup
trap in `UIApplicationEvaluateRuntimeIssueForNoSceneLifecycleAdoption`.
See [Apple's scene migration guide](https://developer.apple.com/documentation/uikit/transitioning-to-the-uikit-scene-based-life-cycle),
[tao issue 1308](https://github.com/tauri-apps/tao/issues/1308), and
[Tauri issue 15719](https://github.com/tauri-apps/tauri/issues/15719).

Remove this patch only after the locked upstream version supports single-scene
lifecycle, preserves scene configuration ownership, and handles cold-start links.
Validate a release build, cold/warm links, and foreground/background calls.
