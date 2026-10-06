"""Release checks must include native group media and accept valid SDK omissions."""
import contextlib
import importlib.util
import io
import plistlib
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("ios_privacy", Path(__file__).resolve().parents[1] / "check_ios_privacy.py")
privacy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(privacy)


class NativeMediaPrivacyTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.app = Path(self.directory.name) / "elo.app"
        self.manifest = {"NSPrivacyTracking": False, "NSPrivacyTrackingDomains": [],
                         "NSPrivacyAccessedAPITypes": [], "NSPrivacyCollectedDataTypes": []}
        paths = ["PrivacyInfo.xcprivacy"]
        paths += [name + ".bundle/PrivacyInfo.xcprivacy" for name in privacy.SDK_BUNDLES]
        paths += ["Frameworks/" + name + ".framework/PrivacyInfo.xcprivacy"
                  for name in ("WebRTC", "LiveKitWebRTC", "RustLiveKitUniFFI")]
        for relative in paths:
            path = self.app / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(plistlib.dumps(self.manifest))

    def check(self):
        with contextlib.redirect_stdout(io.StringIO()):
            privacy.check(self.app, push=True)

    def test_requires_both_dynamic_group_framework_manifests(self):
        for name in ("LiveKitWebRTC", "RustLiveKitUniFFI"):
            path = self.app / "Frameworks" / (name + ".framework") / "PrivacyInfo.xcprivacy"
            original = path.read_bytes()
            path.unlink()
            with self.assertRaisesRegex(AssertionError, "Missing embedded manifest"):
                self.check()
            path.write_bytes(original)
        self.check()

    def test_accepts_livekit_optional_tracking_keys_without_rewriting_its_manifest(self):
        path = self.app / "LiveKit_LiveKit.bundle/PrivacyInfo.xcprivacy"
        data = dict(self.manifest)
        del data["NSPrivacyTracking"]
        del data["NSPrivacyTrackingDomains"]
        path.write_bytes(plistlib.dumps(data))
        original = path.read_bytes()
        self.check()
        self.assertEqual(path.read_bytes(), original)

    def test_rejects_tracking_even_when_other_sdk_manifests_are_valid(self):
        path = self.app / "LiveKit_LiveKit.bundle/PrivacyInfo.xcprivacy"
        path.write_bytes(plistlib.dumps({**self.manifest, "NSPrivacyTracking": True}))
        with self.assertRaisesRegex(AssertionError, "Unexpected tracking"):
            self.check()


if __name__ == "__main__":
    unittest.main()
