"""Operational backup failure and restore checks using synthetic files only."""
import importlib.util
from contextlib import closing
import io
from pathlib import Path
import shutil
import subprocess
import sqlite3
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))

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

    def test_snapshot_decrypts_without_interrupting_services(self):
        archive = backup.snapshot(self.config, self.root)
        clear = subprocess.check_output(['age', '-d', '-i', str(self.root / 'key'), str(archive)])
        with tarfile.open(fileobj=io.BytesIO(clear), mode='r:gz') as tar:
            self.assertEqual(tar.extractfile(str(self.data).lstrip('/')).read(), self.data.read_bytes())
        self.assertFalse(self.calls)
        self.assertFalse(backup.STATE.exists())

    def test_encrypted_archive_contains_verified_attachment_bytes(self):
        from attachment_snapshot import AttachmentSnapshot
        import hashlib
        import json
        content = b'synthetic encrypted attachment'
        space, obj = 'a' * 64, 'b' * 32
        manifest = {'version': 1, 'spaces': {space: {'revision': 'c' * 64,
                    'objects': [{'object': obj, 'size': len(content),
                                 'sha256': hashlib.sha256(content).hexdigest()}]}}}
        self.config['attachments'] = {'operator_url': 'http://127.0.0.1:18901'}
        job = AttachmentSnapshot(self.config['attachments'])
        with patch.object(backup, 'AttachmentSnapshot', return_value=job), patch.object(
                job, 'request', side_effect=lambda path: io.BytesIO(
                    json.dumps(manifest).encode() if path == '/backup/attachments' else content)):
            archive = backup.snapshot(self.config, self.root)
        clear = subprocess.check_output(['age', '-d', '-i', str(self.root / 'key'), str(archive)])
        with tarfile.open(fileobj=io.BytesIO(clear), mode='r:gz') as tar:
            self.assertEqual(tar.extractfile(f'elo-attachments/spaces/{space}/{obj}').read(), content)
            self.assertEqual(json.load(tar.extractfile('elo-attachments/manifest.json')), manifest)
        self.assertFalse(list(self.root.glob('.snapshot-*')))
        self.assertFalse(self.calls)

    def test_capture_failure_removes_plain_staging_and_partial_archive(self):
        with patch.object(backup.subprocess, 'Popen', side_effect=OSError('synthetic failure')):
            # Leave the successful age preflight independent of Popen's failure.
            with patch.object(backup, 'run', side_effect=lambda *a, **kw:
                              None if a[0] == 'age' else self.calls.append(list(a))):
                with self.assertRaises(OSError):
                    backup.snapshot(self.config, self.root)
        self.assertFalse(self.calls)
        self.assertFalse(list(self.root.glob('.snapshot-*')))
        self.assertFalse(backup.STATE.exists())
        self.assertFalse(list(self.root.glob('*.partial')))

    def test_invalid_recipient_never_stops_services(self):
        (self.root / 'recipient').write_text('not-an-age-recipient')
        with self.assertRaises(ValueError):
            backup.snapshot(self.config, self.root)
        self.assertFalse(self.calls)

    def test_online_snapshot_includes_wal_and_preserves_config_links(self):
        state = self.root / 'state'
        state.mkdir()
        db = sqlite3.connect(state / 'state.sqlite')
        self.addCleanup(db.close)
        db.execute('PRAGMA journal_mode=WAL')
        db.execute('CREATE TABLE record (value TEXT)')
        db.execute("INSERT INTO record VALUES ('committed WAL value')")
        db.commit()
        (state / 'setting').write_text('setting')
        (state / 'link').symlink_to('setting')
        self.config['paths'] = [str(state)]
        archive = backup.snapshot(self.config, self.root)
        clear = subprocess.check_output(['age', '-d', '-i', str(self.root / 'key'), str(archive)])
        with tarfile.open(fileobj=io.BytesIO(clear), mode='r:gz') as tar:
            names = tar.getnames()
            self.assertFalse(any(n.endswith(('-wal', '-shm')) for n in names))
            self.assertEqual(tar.getmember(str(state / 'link').lstrip('/')).linkname, 'setting')
            restored = self.root / 'restored.sqlite'
            restored.write_bytes(tar.extractfile(str(state / 'state.sqlite').lstrip('/')).read())
        with closing(sqlite3.connect(restored)) as restored_db:
            self.assertEqual(restored_db.execute('SELECT value FROM record').fetchone(),
                             ('committed WAL value',))
            self.assertEqual(restored_db.execute('PRAGMA integrity_check').fetchone(), ('ok',))
        self.assertFalse(self.calls)

    def test_changing_source_is_retried_but_never_published_after_exhaustion(self):
        with patch.object(backup, 'capture', side_effect=backup.SourceChanged('changed')) as capture:
            with patch.object(backup.time, 'sleep'):
                with self.assertRaises(backup.SourceChanged):
                    backup.snapshot(self.config, self.root)
        self.assertEqual(capture.call_count, 3)
        self.assertFalse(list(self.root.glob('*.age')))
        self.assertFalse(list(self.root.glob('.snapshot-*')))
        self.assertFalse(self.calls)

    def test_write_to_a_previously_copied_database_rejects_mixed_snapshot(self):
        from online_snapshot import capture, inventory, SourceChanged
        first = self.root / 'first.sqlite'
        second = self.root / 'second.sqlite'
        for path in (first, second):
            with closing(sqlite3.connect(path)) as db, db:
                db.execute('CREATE TABLE record (value INTEGER)')
                db.execute('INSERT INTO record VALUES (1)')
        calls = 0

        def changed_inventory(paths):
            nonlocal calls
            calls += 1
            if calls == 2:
                with closing(sqlite3.connect(first)) as db, db:
                    db.execute('UPDATE record SET value=2')
            return inventory(paths)

        with patch('online_snapshot.inventory', side_effect=changed_inventory):
            with self.assertRaises(SourceChanged):
                capture([str(first), str(second)], self.root / 'snapshot')


class RetentionTests(unittest.TestCase):
    def test_interrupted_plain_staging_cleanup_preserves_archives_and_symlink_targets(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            staging = directory / '.snapshot-1234abcd'
            staging.mkdir()
            (staging / 'private.txt').write_text('synthetic')
            target = directory / 'keep'
            target.mkdir()
            (directory / '.snapshot-abcd1234').symlink_to(target, target_is_directory=True)
            archive = directory / 'elo-ops-20260928T000000Z.tar.gz.age'
            archive.write_bytes(b'encrypted fixture')
            partial = directory / (archive.name + '.partial')
            partial.write_bytes(b'incomplete encrypted fixture')
            backup.clean_interrupted_staging(directory)
            self.assertFalse(staging.exists())
            self.assertFalse(partial.exists())
            self.assertTrue(archive.exists())
            self.assertTrue(target.exists())

    def test_retention_only_selects_our_own_old_snapshot_names(self):
        now = backup.dt.datetime(2026, 9, 28, tzinfo=backup.dt.timezone.utc)
        self.assertTrue(backup.expired('elo-ops-20260901T000000Z.tar.gz.age', now))
        for name in ('other.age', '../elo-ops-20260901T000000Z.tar.gz.age',
                     'elo-ops-20260929T000000Z.tar.gz.age', 'elo-ops-20260901T000000Z.tar.gz.age.partial'):
            self.assertFalse(backup.expired(name, now))


if __name__ == '__main__':
    unittest.main()
