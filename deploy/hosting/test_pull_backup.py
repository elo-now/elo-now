"""Remote loss or hostile file names cannot erase independent local snapshots."""
import datetime as dt
from pathlib import Path
import tempfile
import unittest
from pull_backup import candidates, prune, timestamp


class PullTests(unittest.TestCase):
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
