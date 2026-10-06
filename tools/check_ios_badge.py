#!/usr/bin/env python3
"""Exercise production badge reconciliation on a disposable iOS simulator.

Uses synthetic notifications, a separate app ID/container, and only Swift +
Apple SDKs. Does not install on hardware, compile Rust, or contact Firebase.
Requires an installed iOS simulator runtime. All scratch/device state is removed.
"""
import argparse
import json
from pathlib import Path
import plistlib
import platform
import shutil
import subprocess
import tempfile
import time
import uuid


ROOT = Path(__file__).resolve().parents[1]
IOS = ROOT / "crates/tauri-plugin-elo-push/ios"
BUNDLE = "now.elo.badge-harness"


def run(*args, timeout=60, check=True):
    result = subprocess.run(args, text=True, capture_output=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"{args[0]} failed ({result.returncode}): {result.stderr[-5000:]}")
    return result.stdout.strip()


def ordering(scratch):
    sdk = run("xcrun", "--sdk", "macosx", "--show-sdk-path")
    executable = scratch / "PushBadgeOrderingTests"
    run("xcrun", "swiftc", "-swift-version", "5", "-sdk", sdk,
        "-target", platform.machine() + "-apple-macos13.0", "-module-cache-path", str(scratch / "mac-modules"),
        str(IOS / "Sources/PushInbox.swift"), str(IOS / "Sources/PushRegistrations.swift"), str(IOS / "Sources/PushBadge.swift"),
        str(IOS / "Tests/PushBadgeOrderingTests.swift"), "-framework", "UserNotifications",
        "-o", str(executable), timeout=180)
    print(run(str(executable)), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ordering-only", action="store_true", help="Run deterministic callback tests without a simulator")
    args = parser.parse_args()
    if args.ordering_only:
        with tempfile.TemporaryDirectory(prefix="elo-ios-badge-") as scratch:
            ordering(Path(scratch))
        return
    if shutil.disk_usage(tempfile.gettempdir()).free < 4 * 1024**3:
        raise RuntimeError("At least 4 GiB free space is required before this bounded test")
    runtimes = json.loads(run("xcrun", "simctl", "list", "runtimes", "-j"))["runtimes"]
    available = [r for r in runtimes if r.get("isAvailable") and r.get("platform") == "iOS"]
    runtime = max(available, key=lambda r: tuple(int(x) for x in r["version"].split(".")))
    device_type = next(t["identifier"] for t in runtime["supportedDeviceTypes"] if t["name"] == "iPhone 17")
    device = None
    with tempfile.TemporaryDirectory(prefix="elo-ios-badge-") as scratch:
        scratch = Path(scratch)
        ordering(scratch)
        app = scratch / "BadgeHarness.app"
        app.mkdir()
        info = {
            "CFBundleIdentifier": BUNDLE, "CFBundleName": "BadgeHarness",
            "CFBundleExecutable": "BadgeHarness", "CFBundlePackageType": "APPL",
            "CFBundleVersion": "1", "CFBundleShortVersionString": "1.0",
            "MinimumOSVersion": "16.0", "UIDeviceFamily": [1], "LSRequiresIPhoneOS": True,
            "UILaunchScreen": {},
            "UIApplicationSceneManifest": {
                "UIApplicationSupportsMultipleScenes": False,
                "UISceneConfigurations": {
                    "UIWindowSceneSessionRoleApplication": [{
                        "UISceneConfigurationName": "Badge Harness",
                        "UISceneDelegateClassName": "BadgeHarness.BadgeHarnessScene",
                    }],
                },
            },
        }
        (app / "Info.plist").write_bytes(plistlib.dumps(info))
        sdk = run("xcrun", "--sdk", "iphonesimulator", "--show-sdk-path")
        print(f"Building Swift-only harness for iOS {runtime['version']}", flush=True)
        run("xcrun", "swiftc", "-swift-version", "5", "-sdk", sdk,
            "-target", "arm64-apple-ios16.0-simulator", "-module-cache-path", str(scratch / "modules"),
            str(IOS / "Sources/PushInbox.swift"), str(IOS / "Sources/PushRegistrations.swift"), str(IOS / "Sources/PushBadge.swift"),
            str(IOS / "Tests/BadgeHarness.swift"), "-framework", "UIKit", "-framework", "UserNotifications",
            "-o", str(app / "BadgeHarness"), timeout=180)
        run("codesign", "--force", "--sign", "-", str(app))
        try:
            name = "elo Badge QA " + uuid.uuid4().hex[:8]
            device = run("xcrun", "simctl", "create", name, device_type, runtime["identifier"])
            print(f"Created disposable simulator {name} ({device})", flush=True)
            run("xcrun", "simctl", "boot", device)
            run("xcrun", "simctl", "bootstatus", device, "-b", timeout=180)
            run("xcrun", "simctl", "install", device, str(app))
            container = Path(run("xcrun", "simctl", "get_app_container", device, BUNDLE, "data"))

            def phase(name):
                if name == "setup":
                    print("Allow notifications for BadgeHarness in this disposable simulator only.", flush=True)
                stdout = scratch / (name + ".stdout")
                stderr = scratch / (name + ".stderr")
                with stdout.open("w") as out, stderr.open("w") as err:
                    process = subprocess.Popen(["xcrun", "simctl", "launch", "--console",
                        "--terminate-running-process", device, BUNDLE, name], stdout=out, stderr=err)
                    try:
                        result_file = container / "Documents" / (name + ".json")
                        deadline = time.monotonic() + (180 if name == "setup" else 45)
                        while not result_file.exists():
                            if process.poll() is not None or time.monotonic() >= deadline:
                                raise RuntimeError("Harness did not report a result: " + name)
                            time.sleep(0.1)
                        result = json.loads(result_file.read_text())
                        print(json.dumps(result, sort_keys=True), flush=True)
                        if not result["passed"]:
                            raise RuntimeError("Harness failed: " + name)
                    except Exception:
                        for log in [stdout, stderr]:
                            print(log.read_text(errors="replace")[-6000:], flush=True)
                        print(run("xcrun", "simctl", "spawn", device, "log", "show", "--style", "compact",
                            "--last", "2m", "--predicate", 'process == "BadgeHarness"', check=False)[-6000:], flush=True)
                        raise
                    finally:
                        run("xcrun", "simctl", "terminate", device, BUNDLE, check=False)
                        try: process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.terminate()
                            process.wait(timeout=5)

            def push(event):
                payload = {
                    "aps": {"alert": {"title": "Synthetic badge test", "body": "No user data"}, "badge": 1},
                    "elo_registration": "1" * 32, "elo_wake": "1", "elo_category": "message",
                    "elo_scope": "a" * 64, "elo_event": event * 64, "elo_target": "X" * 128,
                }
                path = scratch / "push.json"
                path.write_text(json.dumps(payload))
                run("xcrun", "simctl", "push", device, BUNDLE, str(path))

            phase("setup")
            push("b")
            push("c")
            phase("ack_first")
            push("b")
            phase("restart_late_push")
            phase("ack_last")
            phase("local_unread")
            push("d")
            phase("registration_changes_during_callback")
            print("PASS: six iOS system notification/badge phases; no APNs/FCM or full app claim", flush=True)
        finally:
            if device:
                try:
                    run("xcrun", "simctl", "shutdown", device, timeout=20, check=False)
                finally:
                    run("xcrun", "simctl", "delete", device)
                print("Deleted disposable simulator " + device, flush=True)
    print("Removed harness app, module cache and scratch files", flush=True)


if __name__ == "__main__":
    main()
