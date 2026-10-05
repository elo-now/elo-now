"""Catch native IPC handlers that compile but cannot be called by the local UI."""
import json
from pathlib import Path
import re
import unittest

NATIVE = Path(__file__).resolve().parents[1] / "apps/desktop/src-tauri"


def handler_commands(source):
    # Attributes contain their own brackets and may contain commas.
    handler = re.search(r"tauri::generate_handler!\[((?:[^\[\]]|\[[^\[\]]*\])*)\]", source, re.S)
    if handler is None:
        raise ValueError("Native IPC handler list is missing or malformed")
    items = re.sub(r"#\[[^\[\]]*\]", "", handler.group(1))
    return {item.strip().rsplit("::", 1)[-1] for item in items.split(",") if item.strip()}


class NativePermissions(unittest.TestCase):
    def test_handler_parser_preserves_conditional_and_following_commands(self):
        source = '''tauri::generate_handler![
            open_profile,
            #[cfg(all(desktop, feature = "notifications"))]
            notifications::notify,
            close_profile,
        ]'''
        self.assertEqual(handler_commands(source), {"open_profile", "notify", "close_profile"})

    def test_handlers_are_declared_and_granted_to_the_local_window(self):
        source = (NATIVE / "src/lib.rs").read_text()
        commands = handler_commands(source)
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
