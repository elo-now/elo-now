"""Operational backup failure and restore checks using synthetic files only."""
import importlib.util
import io
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('elo_backup', Path(__file__).with_name('backup.py'))
backup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backup)


@unittest.skipUnless(shutil.which('age') and shutil.which('age-keygen'), 'age tools required')
class BackupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = patch.object(backup, 'STATE', self.root / 'resume.json')
        self.state.start()
        self.addCleanup(self.state.stop)
        subprocess.run(['age-keygen', '-o', str(self.root / 'key')], check=True, capture_output=True)
        (self.root / 'recipient').write_bytes(subprocess.check_output(['age-keygen', '-y', str(self.root / 'key')]))
        self.data = self.root / 'synthetic.txt'
        self.data.write_bytes(b'synthetic encrypted backup check\n')
        self.config = {'recipient_file': str(self.root / 'recipient'), 'services': ['synthetic.service'],
                       'paths': [str(self.data)]}
        self.calls = []
        original = subprocess.run

        def command(args, **kwargs):
            if args[0] == 'systemctl':
                self.calls.append(list(args))
                return subprocess.CompletedProcess(args, 0)
            return original(args, **kwargs)

        self.mock = patch.object(backup.subprocess, 'run', side_effect=command)
        self.mock.start()
        self.addCleanup(self.mock.stop)

    def test_snapshot_decrypts_and_service_is_resumed(self):
        archive = backup.snapshot(self.config, self.root)
        clear = subprocess.check_output(['age', '-d', '-i', str(self.root / 'key'), str(archive)])
        with tarfile.open(fileobj=io.BytesIO(clear), mode='r:gz') as tar:
            self.assertEqual(tar.extractfile(str(self.data).lstrip('/')).read(), self.data.read_bytes())
        self.assertIn(['systemctl', 'stop', 'synthetic.service'], self.calls)
        self.assertIn(['systemctl', 'start', 'synthetic.service'], self.calls)
        self.assertFalse(backup.STATE.exists())

    def test_capture_failure_always_resumes_and_removes_partial_archive(self):
        with patch.object(backup.subprocess, 'Popen', side_effect=OSError('synthetic failure')):
            # Leave the successful age preflight independent of Popen's failure.
            with patch.object(backup, 'run', side_effect=lambda *a, **kw:
                              None if a[0] == 'age' else self.calls.append(list(a))):
                with self.assertRaises(OSError):
                    backup.snapshot(self.config, self.root)
        self.assertIn(['systemctl', 'start', 'synthetic.service'], self.calls)
        self.assertFalse(backup.STATE.exists())
        self.assertFalse(list(self.root.glob('*.partial')))

    def test_invalid_recipient_never_stops_services(self):
        (self.root / 'recipient').write_text('not-an-age-recipient')
        with self.assertRaises(ValueError):
            backup.snapshot(self.config, self.root)
        self.assertFalse(self.calls)


class RetentionTests(unittest.TestCase):
    def test_retention_only_selects_our_own_old_snapshot_names(self):
        now = backup.dt.datetime(2026, 9, 28, tzinfo=backup.dt.timezone.utc)
        self.assertTrue(backup.expired('elo-ops-20260901T000000Z.tar.gz.age', now))
        for name in ('other.age', '../elo-ops-20260901T000000Z.tar.gz.age',
                     'elo-ops-20260929T000000Z.tar.gz.age', 'elo-ops-20260901T000000Z.tar.gz.age.partial'):
            self.assertFalse(backup.expired(name, now))


if __name__ == '__main__':
    unittest.main()
