# mac-usernotifications local patch

Based on crates.io `mac-usernotifications` 0.3.1 (upstream:
https://github.com/hoodie/mac-usernotifications).

`NotificationHandle::response` retains its `PendingGuard` while awaiting the
response or timeout. Upstream consumed the guard using `ManuallyDrop`, leaking
its request-id allocation and leaving the delegate sender registered whenever
a response wait timed out or was cancelled. The patch removes that unsafe move;
normal completion, cancellation and timeout now all release the guard.

The focused regression polls a response without invoking any OS APIs, then
cancels it and verifies that the delegate no longer retains its sender.
No permission, presentation, sound, or notification payload behavior is changed.
