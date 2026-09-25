"""Catch native IPC handlers that compile but cannot be called by the local UI."""
import json
from pathlib import Path
import re
import unittest

NATIVE = Path(__file__).resolve().parents[1] / "apps/desktop/src-tauri"


class NativePermissions(unittest.TestCase):
    def test_handlers_are_declared_and_granted_to_the_local_window(self):
        source = (NATIVE / "src/lib.rs").read_text()
        handler = re.search(r"tauri::generate_handler!\[(.*?)\]", source, re.S)
        self.assertIsNotNone(handler)
        commands = {
            item.strip().rsplit("::", 1)[-1]
            for item in handler.group(1).split(",") if item.strip()
        }
        manifest = (NATIVE / "build.rs").read_text()
        declared = set(re.findall(r'"([a-z_]+)"', manifest.split(".commands(&[", 1)[1].split("]", 1)[0]))
        self.assertEqual(commands, declared, "IPC handlers and build manifest must agree")
        capability = json.loads((NATIVE / "capabilities/main.json").read_text())
        self.assertTrue(capability["local"])
        self.assertNotIn("remote", capability)
        permissions = {p for p in capability["permissions"] if isinstance(p, str)}
        expected = {"allow-" + command.replace("_", "-") for command in commands}
        self.assertFalse(expected - permissions, f"Missing local IPC permissions: {expected - permissions}")


if __name__ == "__main__":
    unittest.main()
