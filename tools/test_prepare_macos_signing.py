import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import plistlib
import tempfile
import unittest

from prepare_macos_signing import APP_ID, DOMAIN, TEAM, validate_profile, write_overlay


class MacSigningTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 10, 2, tzinfo=timezone.utc)
        self.cert = b"fictional public certificate"
        self.identity = hashlib.sha1(self.cert).hexdigest().upper()
        self.profile = {
            "Platform": ["OSX"],
            "TeamIdentifier": [TEAM],
            "ExpirationDate": self.now + timedelta(days=1),
            "ProvisionedDevices": ["fictional-test-mac"],
            "DeveloperCertificates": [self.cert],
            "Entitlements": {
                "com.apple.application-identifier": APP_ID,
                "com.apple.developer.team-identifier": TEAM,
                "com.apple.security.get-task-allow": True,
                "keychain-access-groups": [f"{TEAM}.*"],
                "com.apple.developer.associated-domains": ["*"],
            },
        }

    def validate(self, profile=None, webcredentials=False):
        return validate_profile(profile or self.profile, self.identity, "fictional-test-mac", self.now, webcredentials)

    def test_private_keychain_and_optional_exact_domain_do_not_grant_debugging(self):
        entitlements = self.validate(webcredentials=True)
        self.assertEqual(entitlements["keychain-access-groups"], [APP_ID])
        self.assertEqual(entitlements["com.apple.developer.associated-domains"], [DOMAIN])
        self.assertNotIn("get-task-allow", entitlements)
        self.assertNotIn("com.apple.security.get-task-allow", entitlements)
        self.assertNotIn("com.apple.developer.associated-domains", self.validate())

    def test_wrong_platform_team_app_device_certificate_and_expiry_are_rejected(self):
        mutations = [
            ("Platform", ["iOS"]),
            ("TeamIdentifier", ["OTHERTEAM"]),
            ("ProvisionedDevices", ["another-mac"]),
            ("DeveloperCertificates", [b"another public certificate"]),
            ("ExpirationDate", self.now),
        ]
        for key, value in mutations:
            with self.subTest(key=key):
                profile = copy.deepcopy(self.profile)
                profile[key] = value
                with self.assertRaises(ValueError):
                    self.validate(profile)
        for key, value in [
            ("com.apple.application-identifier", f"{TEAM}.*"),
            ("com.apple.developer.team-identifier", "OTHERTEAM"),
            ("keychain-access-groups", ["OTHERTEAM.*"]),
            ("com.apple.security.get-task-allow", False),
        ]:
            with self.subTest(key=key):
                profile = copy.deepcopy(self.profile)
                profile["Entitlements"][key] = value
                with self.assertRaises(ValueError):
                    self.validate(profile)

    def test_webcredentials_requires_an_authorizing_profile(self):
        self.profile["Entitlements"].pop("com.apple.developer.associated-domains")
        self.validate()
        with self.assertRaisesRegex(ValueError, "Associated Domains"):
            self.validate(webcredentials=True)

    def test_device_bound_macos_profile_can_omit_debugging_entitlement(self):
        self.profile["Entitlements"].pop("com.apple.security.get-task-allow")
        entitlements = self.validate()
        self.assertEqual(entitlements["keychain-access-groups"], [APP_ID])
        self.assertNotIn("com.apple.security.get-task-allow", entitlements)

    def test_overlay_embeds_original_profile_and_protects_output_from_overwrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "signing"
            destination = write_overlay(output, b"fictional CMS bytes", self.identity, self.validate())
            config = json.loads(destination.read_text())["bundle"]["macOS"]
            embedded = Path(config["files"]["embedded.provisionprofile"])
            self.assertEqual(embedded.read_bytes(), b"fictional CMS bytes")
            self.assertEqual(config["signingIdentity"], self.identity)
            self.assertTrue(config["hardenedRuntime"])
            self.assertEqual(plistlib.loads(Path(config["entitlements"]).read_bytes())["com.apple.application-identifier"], APP_ID)
            self.assertEqual(output.stat().st_mode & 0o777, 0o700)
            for path in output.iterdir():
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                write_overlay(output, b"replacement", self.identity, self.validate())
            self.assertEqual(embedded.read_bytes(), b"fictional CMS bytes")


if __name__ == "__main__":
    unittest.main()
