#!/usr/bin/env python3
"""Validate privacy manifests in an actual .app or .xcarchive, not source files."""
import argparse
import plistlib
from pathlib import Path

SDK_BUNDLES = (
    "Firebase_FirebaseCore", "Firebase_FirebaseCoreInternal",
    "Firebase_FirebaseInstallations", "Firebase_FirebaseMessaging",
    "GoogleDataTransport_GoogleDataTransport",
    "GoogleUtilities_GoogleUtilities-AppDelegateSwizzler",
    "GoogleUtilities_GoogleUtilities-Environment", "GoogleUtilities_GoogleUtilities-Logger",
    "GoogleUtilities_GoogleUtilities-NSData", "GoogleUtilities_GoogleUtilities-Network",
    "GoogleUtilities_GoogleUtilities-Reachability", "GoogleUtilities_GoogleUtilities-UserDefaults",
    "Promises_FBLPromises", "nanopb_nanopb",
)


def check(path, push=False):
    app = path
    if path.suffix == ".xcarchive":
        apps = list((path / "Products/Applications").glob("*.app"))
        assert len(apps) == 1, "Expected one application in archive"
        app = apps[0]
    expected = [app / "PrivacyInfo.xcprivacy"]
    if push:
        expected += [app / (name + ".bundle") / "PrivacyInfo.xcprivacy" for name in SDK_BUNDLES]
        expected.append(app / "Frameworks/WebRTC.framework/PrivacyInfo.xcprivacy")
    collected, reasons = set(), set()
    for file in expected:
        assert file.is_file(), f"Missing embedded manifest: {file.relative_to(app)}"
        data = plistlib.loads(file.read_bytes())
        assert data.get("NSPrivacyTracking") is False, f"Unexpected tracking: {file.name}"
        assert data.get("NSPrivacyTrackingDomains") == [], "Review tracking domains"
        for item in data.get("NSPrivacyAccessedAPITypes", []):
            assert item["NSPrivacyAccessedAPITypeReasons"], "Empty API reasons"
            reasons.add(item["NSPrivacyAccessedAPIType"])
        for item in data.get("NSPrivacyCollectedDataTypes", []):
            assert type(item["NSPrivacyCollectedDataTypeLinked"]) is bool
            assert item["NSPrivacyCollectedDataTypeTracking"] is False
            assert item["NSPrivacyCollectedDataTypePurposes"]
            collected.add(item["NSPrivacyCollectedDataType"])
    assert not list(app.glob("*.a")), "Static libraries must not be shipped as app resources"
    print(f"Validated {len(expected)} embedded privacy manifests.")
    print("Required-reason categories: " + ", ".join(sorted(reasons)))
    print("Collected-data categories (app and SDK union): " + ", ".join(sorted(collected)))
    print("This check does not replace Xcode's final privacy report or operator disclosure review.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--push", action="store_true")
    args = parser.parse_args()
    check(args.archive, args.push)
