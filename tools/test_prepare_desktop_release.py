import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from prepare_desktop_release import prepare


class ReleaseConfigurationTests(unittest.TestCase):
    source = {"version": "1.0.5", "bundle": {"macOS": {"bundleVersion": "1114"}}}
    legacy = {"RELEASE_SPACE_HOST_URL": "https://old.example.test/spaces/v1/create",
              "RELEASE_WAKE_URL": "https://old.example.test"}
    explicit = {"RELEASE_API_URL": "https://api.example.test", "RELEASE_VERSION": "1.0.6",
                "RELEASE_BUILD_NUMBER": "1137", "RELEASE_WITNESS_URL": "https://witness.example.test/witness/v1",
                "RELEASE_WITNESS_PUBLIC_KEY": "ab" * 32, "RELEASE_WITNESS_KEY_GENERATION": "1",
                "RELEASE_STORAGE_URL": "https://witness.example.test/storage/v1"}

    def test_empty_dispatch_preserves_legacy_publisher_settings(self):
        config, env = prepare(self.legacy, self.source, "Linux")
        self.assertEqual(config, self.source)
        self.assertEqual(set(env), {"TAURI_ELO_SPACE_HOST_URL", "TAURI_ELO_WAKE_URL"})

    def test_api_override_omits_conflicting_legacy_variables_and_preserves_public_pins(self):
        config, env = prepare(self.legacy | self.explicit, self.source, "macOS")
        self.assertEqual(config["version"], "1.0.6")
        self.assertEqual(config["bundle"]["macOS"], {"bundleVersion": "1137", "signingIdentity": "-"})
        self.assertNotIn("TAURI_ELO_SPACE_HOST_URL", env)
        self.assertNotIn("TAURI_ELO_WAKE_URL", env)
        for name in ("API_URL", "WITNESS_URL", "WITNESS_PUBLIC_KEY", "WITNESS_KEY_GENERATION", "STORAGE_URL"):
            self.assertEqual(env[f"TAURI_ELO_{name}"], self.explicit[f"RELEASE_{name}"])

    def test_missing_endpoints_fail_before_compilation(self):
        with self.assertRaises(ValueError):
            prepare({}, self.source, "Linux")

    def test_invalid_urls_and_credentials_are_rejected(self):
        for url in ("http://api.example.test", "https://user:secret@api.example.test", "https://api.example.test?",
                    "https://api.example.test#secret", "https://api.example.test/path", "https://api.example.test\nX=bad",
                    "https://api.example.test:0", "https://api.example.test:99999", "https://bad host.test",
                    "https://api.example.test\\@evil.test", "https://api.example.test/%2f", "https://-"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                prepare(self.explicit | {"RELEASE_API_URL": url}, self.source, "Linux")

    def test_all_service_urls_use_their_canonical_paths(self):
        for name in ("WITNESS_URL", "STORAGE_URL"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                prepare(self.explicit | {f"RELEASE_{name}": "https://example.test/"}, self.source, "Linux")

    def test_witness_requires_complete_valid_pins(self):
        for name, values in {"WITNESS_PUBLIC_KEY": ("", "AB" * 32, "g" * 64, "ab" * 31),
                             "WITNESS_KEY_GENERATION": ("", "0", "-1", "1.0", "01", str(2**53))}.items():
            for value in values:
                with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                    prepare(self.explicit | {f"RELEASE_{name}": value}, self.source, "Linux")

    def test_version_and_build_cannot_be_partial_or_invalid(self):
        for name, values in {"VERSION": ("", "1.0.6-beta", "1.0", "01.0.6", "1.0.6\nX=bad", "65536.0.0"),
                             "BUILD_NUMBER": ("", "0", "-1", "1.2", "01137", "2147483648")}.items():
            for value in values:
                with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                    prepare(self.explicit | {f"RELEASE_{name}": value}, self.source, "Windows")

    def test_https_ipv6_origin_and_non_default_ports_remain_supported(self):
        _, env = prepare(self.explicit | {"RELEASE_API_URL": "https://[2001:db8::1]:9443/"}, self.source, "Linux")
        self.assertEqual(env["TAURI_ELO_API_URL"], "https://[2001:db8::1]:9443/")

    def test_cli_writes_the_config_and_only_validated_nonempty_build_environment(self):
        with tempfile.TemporaryDirectory() as folder:
            output, github_env = Path(folder) / "release.json", Path(folder) / "github-env"
            env = os.environ | self.explicit | self.legacy | {
                "RUNNER_OS": "Windows", "GITHUB_ENV": str(github_env), "GITHUB_SHA": "a" * 40}
            subprocess.run([sys.executable, str(Path(__file__).with_name("prepare_desktop_release.py")),
                            "--output", str(output)], env=env, check=True,
                           cwd=Path(__file__).resolve().parent.parent, capture_output=True)
            exported = dict(line.split("=", 1) for line in github_env.read_text().splitlines())
            self.assertEqual(exported["TAURI_ELO_API_URL"], self.explicit["RELEASE_API_URL"])
            self.assertNotIn("TAURI_ELO_SPACE_HOST_URL", exported)
            self.assertNotIn("TAURI_ELO_WAKE_URL", exported)
            self.assertTrue(all(exported.values()))
            self.assertEqual(json.loads(output.read_text())["version"], "1.0.6")
            metadata = json.loads(output.with_name("desktop-release-metadata.json").read_text())
            self.assertEqual(metadata["build"], "1137")
            self.assertEqual(metadata["commit"], "a" * 40)
            self.assertNotIn("ELO_DESKTOP_CONFIG", metadata["public_configuration"])


if __name__ == "__main__":
    unittest.main()
