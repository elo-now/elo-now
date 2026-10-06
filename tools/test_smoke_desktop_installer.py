import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from smoke_desktop_installer import final_installer, require_display, wait_for_startup


class InstalledStartupTests(unittest.TestCase):
    def clock(self):
        current = [0.0]
        return lambda: current[0], lambda seconds: current.__setitem__(0, current[0] + seconds)

    def test_healthy_visible_window_must_stay_open_for_ten_seconds(self):
        clock, sleep = self.clock()
        process = Mock(poll=Mock(return_value=None))
        elapsed = wait_for_startup(process, lambda: clock() >= 3, clock=clock, sleep=sleep)
        self.assertEqual(elapsed, 13)

    def test_process_without_window_cannot_pass(self):
        clock, sleep = self.clock()
        with self.assertRaisesRegex(RuntimeError, "visible window"):
            wait_for_startup(Mock(poll=Mock(return_value=None)), lambda: False, clock=clock, sleep=sleep)

    def test_early_exit_cannot_pass_even_after_window_appeared(self):
        clock, sleep = self.clock()
        process = Mock(poll=lambda: 0 if clock() > 2 else None, returncode=0)
        with self.assertRaisesRegex(RuntimeError, "exited during startup"):
            wait_for_startup(process, lambda: True, clock=clock, sleep=sleep)

    def test_disappearing_window_resets_the_stability_period(self):
        clock, sleep = self.clock()
        elapsed = wait_for_startup(Mock(poll=Mock(return_value=None)), lambda: not 4 <= clock() < 6,
                                   clock=clock, sleep=sleep)
        self.assertEqual(elapsed, 16)

    def test_headless_linux_is_a_failure_not_a_skip(self):
        with patch.dict(os.environ, {}, clear=True), self.assertRaisesRegex(RuntimeError, "graphical display"):
            require_display("linux")

    def test_installer_selection_rejects_wrong_versions_and_ambiguous_outputs(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            candidate = root / "elo.now_1.0.6_amd64.deb"
            candidate.write_bytes(b"fixture")
            self.assertEqual(final_installer(root, ".deb", "1.0.6"), candidate.resolve())
            with self.assertRaises(RuntimeError):
                final_installer(root, ".deb", "1.0.5")
            (root / "stale.deb").write_bytes(b"fixture")
            with self.assertRaises(RuntimeError):
                final_installer(root, ".deb", "1.0.6")


if __name__ == "__main__":
    unittest.main()
