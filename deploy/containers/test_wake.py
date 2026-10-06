"""Private VoIP configuration reaches only the relay process."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("wake_launcher", Path(__file__).with_name("wake.py"))
wake = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wake)


class WakeLauncher(unittest.TestCase):
    def test_optional_apns_uses_path_without_exposing_key_or_changing_host(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "config.json").write_text(json.dumps({"public_url": "https://test.example:9443"}))
            plain = wake.command(directory, "127.0.0.1:8878")
            self.assertNotIn("--apns", plain)
            (directory / "apns.json").write_text("synthetic private key")
            enabled = wake.command(directory, "127.0.0.1:8878")
            self.assertEqual(enabled, plain + ["--apns", str(directory / "apns.json")])
            self.assertNotIn("synthetic private key", " ".join(enabled))
            self.assertIn("https://test.example:9443", enabled)
            self.assertIn("127.0.0.1:8878", enabled)

    def test_unknown_settings_do_not_silently_start_a_different_relay(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "config.json").write_text(json.dumps({"public_url": "https://test.example", "sandbox": True}))
            with self.assertRaises(ValueError):
                wake.command(directory, "127.0.0.1:8788")


if __name__ == "__main__":
    unittest.main()
