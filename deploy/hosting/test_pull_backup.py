"""Remote loss or hostile file names cannot erase independent local snapshots."""
import datetime as dt
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import pull_backup
from pull_backup import candidates, download_budget, prune, read_inventory, timestamp


class PullTests(unittest.TestCase):
    def test_remote_inventory_output_is_bounded(self):
        with patch.object(pull_backup, 'MAX_INVENTORY_BYTES', 1024):
            with self.assertRaises(ValueError):
                read_inventory([sys.executable, '-c', 'import sys; sys.stdout.write("x" * 2048)'])

    def test_directory_and_free_disk_limits_preserve_existing_copies(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            existing = directory / 'existing.age'
            existing.write_bytes(b'x' * 18)
            with patch.object(pull_backup, 'MAX_ARCHIVE_BYTES', 100), \
                 patch.object(pull_backup, 'MAX_DIRECTORY_BYTES', 32), \
                 patch.object(pull_backup, 'MIN_FREE_BYTES', 16):
                with patch.object(pull_backup.shutil, 'disk_usage', return_value=SimpleNamespace(free=100)):
                    self.assertEqual(download_budget(directory), 14)
                with patch.object(pull_backup.shutil, 'disk_usage', return_value=SimpleNamespace(free=20)):
                    self.assertEqual(download_budget(directory), 4)
                with patch.object(pull_backup.shutil, 'disk_usage', return_value=SimpleNamespace(free=16)):
                    with self.assertRaises(RuntimeError):
                        download_budget(directory)
            self.assertEqual(existing.read_bytes(), b'x' * 18)

    @unittest.skipUnless(shutil.which('age') and shutil.which('age-keygen'), 'age tools required')
    def test_pull_downloads_only_newest_snapshot_from_many_remote_candidates(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            key = root / 'key'
            subprocess.run(['age-keygen', '-o', str(key)], check=True, capture_output=True)
            recipient = subprocess.check_output(['age-keygen', '-y', str(key)]).decode().strip()
            encrypted = root / 'encrypted.age'
            with encrypted.open('wb') as output:
                subprocess.run(['age', '-r', recipient], input=b'synthetic backup', stdout=output, check=True)
            now = dt.datetime.now(dt.timezone.utc)
            names = ['elo-ops-' + (now - dt.timedelta(minutes=n)).strftime('%Y%m%dT%H%M%SZ')
                     + '.tar.gz.age' for n in range(20)]
            ssh = root / 'ssh'
            log = root / 'requested.json'
            ssh.write_text('#!' + sys.executable + '\n'
                           'import json, pathlib, sys\n'
                           'if sys.argv[-1] == "--list-encrypted":\n'
                           ' print(' + repr(json.dumps(names)) + ')\n'
                           'else:\n'
                           ' pathlib.Path(' + repr(str(log)) + ').write_text(json.dumps(sys.argv[-1]))\n'
                           ' sys.stdout.buffer.write(pathlib.Path(' + repr(str(encrypted)) + ').read_bytes())\n')
            ssh.chmod(0o700)
            destination = root / 'copies'
            config = {'destination': str(destination), 'ssh': str(ssh), 'ssh_key': 'synthetic',
                      'host': 'synthetic', 'age': shutil.which('age'), 'age_key': str(key)}
            with patch.object(pull_backup.shutil, 'disk_usage', return_value=SimpleNamespace(free=16 * 1024**3)):
                pull_backup.pull(config)
            self.assertEqual(json.loads(log.read_text()), names[0])
            self.assertEqual([p.name for p in destination.iterdir()], [names[0]])
            newer = 'elo-ops-' + (now + dt.timedelta(seconds=1)).strftime('%Y%m%dT%H%M%SZ') + '.tar.gz.age'
            ssh.write_text(ssh.read_text().replace(repr(json.dumps(names)), repr(json.dumps([newer, *names]))))
            with patch.object(pull_backup, 'download_budget', return_value=encrypted.stat().st_size - 1):
                with self.assertRaises(ValueError):
                    pull_backup.pull(config)
            # A transfer exceeding the total disk budget leaves no partial data
            # and cannot displace the independently stored previous backup.
            self.assertEqual([p.name for p in destination.iterdir()], [names[0]])

    def test_inventory_only_accepts_recent_plain_archive_names(self):
        now = dt.datetime(2026, 9, 28, tzinfo=dt.timezone.utc)
        safe = 'elo-ops-20260928T000000Z.tar.gz.age'
        self.assertEqual(candidates([safe, safe, '../' + safe, '$(id)',
                                    'elo-ops-20260101T000000Z.tar.gz.age',
                                    'elo-ops-20990101T000000Z.tar.gz.age'], now), [safe])
        with self.assertRaises(ValueError):
            timestamp('../' + safe)

    def test_local_retention_keeps_two_copies_and_never_traverses_links(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            names = ['elo-ops-20260901T000000Z.tar.gz.age',
                     'elo-ops-20260902T000000Z.tar.gz.age',
                     'elo-ops-20260903T000000Z.tar.gz.age']
            for name in names:
                (directory / name).write_bytes(b'encrypted fixture')
            unrelated = directory / 'other-file'
            unrelated.write_bytes(b'keep')
            link = directory / 'elo-ops-20260801T000000Z.tar.gz.age'
            link.symlink_to(unrelated)
            prune(directory, dt.datetime(2026, 9, 28, tzinfo=dt.timezone.utc))
            self.assertFalse((directory / names[0]).exists())
            self.assertTrue(all((directory / n).exists() for n in names[1:]))
            self.assertTrue(link.is_symlink())
            self.assertEqual(unrelated.read_bytes(), b'keep')
