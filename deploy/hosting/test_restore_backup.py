"""Isolated restore acceptance using local synthetic inputs and age keys."""
import io
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import backup
import restore_backup


@unittest.skipUnless(shutil.which('age') and shutil.which('age-keygen'), 'age tools required')
class RestoreTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.key = self.root / 'key'
        subprocess.run(['age-keygen', '-o', str(self.key)], check=True, capture_output=True)
        self.recipient = subprocess.check_output(['age-keygen', '-y', str(self.key)]).decode().strip()
        self.config = {'age_key': str(self.key), 'required_paths': ['/state']}

    def archive(self, members):
        plain = io.BytesIO()
        with tarfile.open(fileobj=plain, mode='w:gz') as stream:
            for name, kind, content in members:
                member = tarfile.TarInfo(name)
                member.type = kind
                if kind == tarfile.REGTYPE:
                    member.size = len(content)
                elif kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                    member.linkname = content.decode()
                stream.addfile(member, io.BytesIO(content) if kind == tarfile.REGTYPE else None)
        path = self.root / 'backup.age'
        path.write_bytes(subprocess.check_output(['age', '-r', self.recipient], input=plain.getvalue()))
        return path

    def test_online_wal_snapshot_restores_without_keys_or_runtime_state(self):
        state = self.root / 'state'
        state.mkdir(mode=0o700)
        db = sqlite3.connect(state / 'data.sqlite')
        self.addCleanup(db.close)
        db.execute('PRAGMA journal_mode=WAL')
        db.execute('CREATE TABLE records(value TEXT)')
        db.execute("INSERT INTO records VALUES ('committed WAL value')")
        db.commit()
        self.assertTrue((state / 'data.sqlite-wal').exists())
        (self.root / 'recipient').write_text(self.recipient)
        with patch.dict(os.environ, {'COPYFILE_DISABLE': '1'}):
            archive = backup.snapshot({'recipient_file': str(self.root / 'recipient'),
                                       'paths': [str(state)]}, self.root)
        destination = self.root / 'restored'
        report = restore_backup.restore({**self.config, 'required_paths': [str(state)]}, archive, destination)
        restored = destination / str(state).lstrip('/') / 'data.sqlite'
        connection = sqlite3.connect(restored)
        self.addCleanup(connection.close)
        self.assertEqual(connection.execute('SELECT value FROM records').fetchone()[0], 'committed WAL value')
        self.assertFalse(report['services_started'])
        self.assertFalse(any(p.name in ('key', 'activation.json', 'startup.json') for p in destination.rglob('*')))
        self.assertFalse(list(destination.rglob('*-wal')))
        self.assertEqual(restored.stat().st_mode & 0o777, 0o600)

    def test_rejects_links_traversal_duplicates_and_unexpected_roots(self):
        for bad in [('state/link', tarfile.SYMTYPE, b'/etc'),
                    ('state/link', tarfile.LNKTYPE, b'state/file'),
                    ('state/../../outside', tarfile.REGTYPE, b'x'),
                    ('unexpected/file', tarfile.REGTYPE, b'x'),
                    ('state/file', tarfile.REGTYPE, b'duplicate')]:
            with self.subTest(bad=bad[:2]):
                archive = self.archive([('state', tarfile.DIRTYPE, b''),
                                        ('state/file', tarfile.REGTYPE, b'x'), bad])
                with self.assertRaises(ValueError):
                    restore_backup.restore(self.config, archive, self.root / 'restored')
                self.assertFalse((self.root / 'restored').exists())
                self.assertFalse(list(self.root.glob('.restore-*')))

    def test_ciphertext_authentication_failure_never_publishes_plaintext(self):
        archive = self.archive([('state', tarfile.DIRTYPE, b''), ('state/file', tarfile.REGTYPE, os.urandom(100_000))])
        archive.write_bytes(archive.read_bytes()[:-1])
        with self.assertRaises((ValueError, tarfile.TarError, EOFError)):
            restore_backup.restore(self.config, archive, self.root / 'restored')
        self.assertFalse((self.root / 'restored').exists())
        self.assertFalse(list(self.root.glob('.restore-*')))

    def test_existing_destination_and_symlink_parent_are_never_modified(self):
        archive = self.archive([('state', tarfile.DIRTYPE, b'')])
        destination = self.root / 'existing'
        destination.mkdir()
        (destination / 'keep').write_text('unchanged')
        with self.assertRaises(FileExistsError):
            restore_backup.restore(self.config, archive, destination)
        self.assertEqual((destination / 'keep').read_text(), 'unchanged')
        link = self.root / 'link'
        link.symlink_to(destination, target_is_directory=True)
        with self.assertRaises(ValueError):
            restore_backup.restore(self.config, archive, link / 'child')

    def test_expansion_limit_removes_partial_restore(self):
        archive = self.archive([('state', tarfile.DIRTYPE, b''), ('state/file', tarfile.REGTYPE, b'ab')])
        with patch.object(restore_backup, 'MAX_EXPANDED_BYTES', 1), self.assertRaises(ValueError):
            restore_backup.restore(self.config, archive, self.root / 'restored')
        self.assertFalse((self.root / 'restored').exists())
        self.assertFalse(list(self.root.glob('.restore-*')))


if __name__ == '__main__':
    unittest.main()
