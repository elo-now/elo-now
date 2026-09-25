#!/usr/bin/env python3
"""Check the actual app's single-window iOS scene declaration before delivery."""
import argparse
import plistlib
from pathlib import Path
from zipfile import ZipFile


def check(path):
    if path.suffix == ".ipa":
        with ZipFile(path) as archive:
            candidates = [name for name in archive.namelist()
                          if name.startswith("Payload/") and name.endswith(".app/Info.plist")
                          and name.count("/") == 2]
            assert len(candidates) == 1, "Expected exactly one app in IPA"
            data = plistlib.loads(archive.read(candidates[0]))
        check_manifest(data)
        return
    if path.suffix == ".xcarchive":
        apps = list((path / "Products/Applications").glob("*.app"))
        assert len(apps) == 1, "Expected exactly one app"
        path = apps[0]
    if path.is_dir():
        path = path / "Info.plist"
    data = plistlib.loads(path.read_bytes())
    check_manifest(data)


def check_manifest(data):
    manifest = data.get("UIApplicationSceneManifest", {})
    assert manifest.get("UIApplicationSupportsMultipleScenes") is False, "Keep single-window support"
    scenes = manifest.get("UISceneConfigurations", {}).get("UIWindowSceneSessionRoleApplication", [])
    assert len(scenes) == 1, "One static scene configuration is required on iOS 27"
    assert scenes[0].get("UISceneDelegateClassName") == "TaoSceneDelegate", "Scene delegate must match Tao's runtime class"
    assert scenes[0].get("UISceneConfigurationName") == "TaoScene", "Scene name must match Tao"
    assert data.get("UISupportedInterfaceOrientations") == ["UIInterfaceOrientationPortrait"]
    if "UIDeviceFamily" in data:
        assert data["UIDeviceFamily"] == [1], "This release targets iPhone"
    print("PASS: explicit single-window Tao scene, portrait orientation and iPhone target.")
    print("Release launch and cold/warm link tests are still required on iOS/iPadOS 27.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("app_or_plist", type=Path)
    check(parser.parse_args().app_or_plist)
