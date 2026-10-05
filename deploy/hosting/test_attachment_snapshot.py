"""Ciphertext backup integrity, completeness and resource-bound checks."""
import copy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from attachment_snapshot import AttachmentSnapshot
from online_snapshot import SourceChanged


class AttachmentSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.access_key = self.root / 'backup.key'
        self.access_key.write_text('a' * 64)
        self.access_key.chmod(0o600)
        self.data = b'synthetic ciphertext bytes'
        self.space, self.obj = 'a' * 64, 'b' * 32
        self.manifest = {'version': 1, 'spaces': {self.space: {
            'revision': 'c' * 64, 'objects': [{'object': self.obj, 'size': len(self.data),
                                              'sha256': hashlib.sha256(self.data).hexdigest()}]}}}
        self.job = AttachmentSnapshot({'operator_url': 'http://127.0.0.1:18901', 'access_key_file': str(self.access_key)})
        def request(path):
            return io.BytesIO(json.dumps(self.manifest).encode() if path == '/backup/attachments' else self.data)
        self.patch = patch.object(self.job, 'request', side_effect=request)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.disk = patch('attachment_snapshot.shutil.disk_usage', return_value=type('Disk', (), {'free': 20 * 1024**3}))
        self.disk.start()
        self.addCleanup(self.disk.stop)

    def test_copy_restores_exact_ciphertext_and_manifest(self):
        manifest = self.job.capture(self.root)
        self.job.verify_unchanged(manifest)
        self.assertEqual((self.root / 'elo-attachments/spaces' / self.space / self.obj).read_bytes(), self.data)
        self.assertEqual(json.loads((self.root / 'elo-attachments/manifest.json').read_text()), self.manifest)

    def test_missing_truncated_oversized_or_corrupted_object_fails(self):
        for content in (b'', self.data[:-1], self.data + b'x', b'x' * len(self.data)):
            with self.subTest(content=content), tempfile.TemporaryDirectory() as temporary:
                with patch.object(self.job, 'request', side_effect=lambda p: io.BytesIO(
                        json.dumps(self.manifest).encode() if p == '/backup/attachments' else content)):
                    with self.assertRaises(ValueError):
                        self.job.capture(Path(temporary).resolve())

    def test_concurrent_metadata_change_rejects_snapshot(self):
        before = self.job.capture(self.root)
        self.manifest['spaces'][self.space]['revision'] = 'd' * 64
        with self.assertRaises(SourceChanged):
            self.job.verify_unchanged(before)

    def test_inventory_rejects_traversal_duplicate_oversize_and_budget(self):
        original = copy.deepcopy(self.manifest)
        entry = original['spaces'][self.space]['objects'][0]
        for changes in ({'object': '../escape'}, {'size': 7 * 1024**2}, {'size': -1}, {'sha256': 'bad'}):
            with self.subTest(changes=changes):
                self.manifest['spaces'][self.space]['objects'] = [{**entry, **changes}]
                with self.assertRaises(ValueError): self.job.inventory()
        self.manifest['spaces'][self.space]['objects'] = [entry, entry]
        with self.assertRaises(ValueError): self.job.inventory()
        self.manifest = original
        self.job.maximum = 1
        with self.assertRaises(ValueError): self.job.inventory()

    def test_remote_origins_and_credential_urls_are_rejected(self):
        for url in ('https://example.test', 'http://127.0.0.1@evil.test', 'http://user:password@127.0.0.1', 'http://127.0.0.1/?secret'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                AttachmentSnapshot({'operator_url': url})

    def test_requests_authenticate_without_redirecting_or_exposing_key_in_url(self):
        self.patch.stop()
        with patch.object(self.job.http, 'open', return_value=io.BytesIO(b'{}')) as opened:
            self.job.request('/backup/attachments')
        request = opened.call_args.args[0]
        self.assertEqual(request.full_url, 'http://127.0.0.1:18901/backup/attachments')
        self.assertEqual(request.get_header('Authorization'), 'Bearer ' + 'a' * 64)

    def test_access_key_must_exist_be_private_and_not_be_a_symlink(self):
        config = {'operator_url': 'http://127.0.0.1:18901', 'access_key_file': str(self.access_key)}
        self.access_key.chmod(0o644)
        with self.assertRaises(ValueError):
            AttachmentSnapshot(config)
        self.access_key.chmod(0o600)
        link = self.root / 'key-link'
        link.symlink_to(self.access_key)
        with self.assertRaises(OSError):
            AttachmentSnapshot({**config, 'access_key_file': str(link)})
