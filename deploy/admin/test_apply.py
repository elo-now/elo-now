"""Privilege-boundary and crash-recovery tests without root, Docker or providers."""
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))
import apply as worker_module
from schema import validate_configuration


class WorkerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.admin = self.root / 'admin'
        self.state = self.root / 'state'
        for relative in ('admin/queue', 'admin/status', 'state/api/config', 'state/export/config',
                         'state/public', 'state/storage/config'):
            (self.root / relative).mkdir(parents=True, mode=0o700, exist_ok=True)
        for target, replacement in (('ROOT_UID', os.getuid()), ('ADMIN_UID', os.getuid())):
            context = patch.object(worker_module, target, replacement)
            context.start()
            self.addCleanup(context.stop)
        # Only ownership assignment is simulated. Real no-follow opens, fsyncs,
        # permission checks, atomic replacement and flock still execute.
        context = patch.object(worker_module.os, 'fchown', lambda *args: None)
        context.start()
        self.addCleanup(context.stop)
        context = patch.object(worker_module.subprocess, 'run', side_effect=AssertionError('Unexpected external command'))
        context.start()
        self.addCleanup(context.stop)
        self.settings = {'role': 'api', 'state_root': str(self.state), 'admin_root': str(self.admin),
                         'container_bundle': str(Path(__file__).resolve().parents[1] / 'containers'), 'version': 'test'}
        self.body = {'name': 'Before', 'message_lifetimes': [86400], 'default_message_lifetime': 86400,
                     'revision': 4, 'url': 'https://api.example', 'public_key': 'a' * 64,
                     'witness': {'url': 'https://witness.example', 'public_key': 'b' * 64},
                     'push_url': 'https://push.example', 'call_url': 'https://calls.example/calls/v1',
                     'storage': {'url': 'https://storage.example', 'public_key': 'c' * 64, 'managed': None}}
        self.write('api/config/config.json', {'allowed_creators': None, 'allowed_message_retentions': [86400],
                                            'secret_key': 'PRIVATE_API_KEY'})
        self.write('export/config/manifest-input.json', self.body)
        self.write('public/hosting-profile.json', {'record': 'old-record', 'link': 'elo://hosting/v1#old'})
        for name in ('hosting-link.txt', 'hosting-qr.svg', 'hosting-profile.html'):
            (self.state / 'public' / name).write_bytes(b'old-public-output')
        self.write('storage/config/config.json', {'public_url': 'https://storage.example'})
        (self.state / 'compose.env').write_text('ELO_STORAGE_IMAGE=elo-storage-mega\nELO_VERSION=test\n')
        self.worker = worker_module.Worker(self.settings)
        self.worker.sign = lambda body: ({'record': 'signed-test-record', 'link': 'elo://hosting/v1#new'}, b'<svg></svg>')
        self.worker.restart = lambda: None
        self.value = {'name': 'After', 'message_lifetimes': [86400, 'no_expiry'], 'default_message_lifetime': 'no_expiry',
                      'creation_mode': 'allowlist', 'allowed_creators': ['d' * 64], 'managed_provider': 's3'}
        self.identifier = 'a' * 32

    def write(self, relative, value):
        path = self.state / relative
        path.write_bytes(worker_module.encoded(value))
        path.chmod(0o600)

    def queue(self, configuration=None, **changes):
        value = {'v': 1, 'id': self.identifier, 'role': self.worker.role, 'created_at': int(time.time()),
                 'configuration': configuration if configuration is not None else self.value}
        value.update(changes)
        path = self.admin / 'queue' / (self.identifier + '.json')
        path.write_bytes(worker_module.encoded(value))
        path.chmod(0o600)
        return path

    def status(self):
        return json.loads((self.admin / 'status' / (self.identifier + '.json')).read_bytes())

    def witness(self):
        self.worker = worker_module.Worker(self.settings | {'role': 'witness'})
        self.worker.restart = lambda: None
        provider = {'provider': 'mega_folder', 'folder_link': 'https://mega.nz/folder/abcdefgh#' + 'x' * 22,
                    'write_auth': 'SENSITIVE' * 4}
        self.write('storage/config/config.json', {'public_url': 'https://storage.example',
                                                'managed_storage': '/etc/elo/storage/managed-storage.json'})
        self.write('storage/config/managed-storage.json', {'provider': provider, 'allowed_owners': []})
        return provider

    def test_api_update_preserves_endpoint_and_key_pins_and_publishes_matching_files(self):
        signed = []
        self.worker.sign = lambda body: (signed.append(copy.deepcopy(body)) or
                                         {'record': 'signed-test-record', 'link': 'elo://hosting/v1#new'}, b'<svg></svg>')
        job = self.queue()
        self.worker.run()
        self.assertEqual(self.status()['status'], 'succeeded')
        self.assertFalse(job.exists())
        current = self.worker.load('export/config/manifest-input.json')
        self.assertEqual(current['revision'], 5)
        self.assertEqual(signed, [current])
        for key in ('url', 'public_key', 'witness', 'push_url', 'call_url'):
            self.assertEqual(current[key], self.body[key])
        self.assertEqual(current['storage']['public_key'], self.body['storage']['public_key'])
        self.assertEqual(current['storage']['managed'], {'provider': 's3', 'retention_hours': 1})
        self.assertEqual(self.worker.load('api/config/config.json')['secret_key'], 'PRIVATE_API_KEY')
        self.assertEqual((self.state / 'public/hosting-link.txt').read_text(), 'elo://hosting/v1#new\n')
        self.assertIn(b'elo://hosting/v1#new', (self.state / 'public/hosting-profile.html').read_bytes())
        self.assertEqual((self.state / 'public/hosting-qr.svg').read_bytes(), b'<svg></svg>')
        self.assertNotIn('PRIVATE_API_KEY', (self.admin / 'state.json').read_text())
        self.assertEqual(list(self.worker.transactions.glob('*.json')), [])

    def test_queue_lock_is_released_before_service_restart(self):
        observed = []
        def restart():
            with self.worker.queue_lock():
                observed.append(True)
        self.worker.restart = restart
        self.queue()
        self.worker.run()
        self.assertEqual(observed, [True])

    def test_failed_restart_restores_all_files_and_records_only_safe_error(self):
        before = {str(path.relative_to(self.state)): path.read_bytes() for path in self.state.rglob('*') if path.is_file()}
        calls = []
        def restart():
            calls.append(True)
            if len(calls) == 1:
                raise ValueError('SENSITIVE provider response')
        self.worker.restart = restart
        self.queue()
        self.worker.run()
        self.assertEqual(len(calls), 2)
        self.assertEqual(self.status(), {'id': self.identifier, 'status': 'failed', 'error': 'configuration_not_applied'})
        for name, content in before.items():
            self.assertEqual((self.state / name).read_bytes(), content, name)
        self.assertNotIn('SENSITIVE', ''.join(path.read_text() for path in (self.admin / 'status').glob('*.json')))

    def test_committed_configuration_stays_successful_after_transient_state_write_failure(self):
        refresh = self.worker.refresh
        calls = []
        def interrupted():
            calls.append(True)
            if len(calls) == 2:
                raise OSError('simulated write failure after commit')
            refresh()
        self.worker.refresh = interrupted
        self.queue()
        self.worker.run()
        self.assertEqual(self.status()['status'], 'succeeded')
        self.assertEqual(self.worker.load('export/config/manifest-input.json')['revision'], 5)
        self.assertEqual(len(calls), 3)

    def test_committed_journal_recovers_on_next_run_without_second_restart_or_revision(self):
        refresh = self.worker.refresh
        calls = []
        def interrupted():
            calls.append(True)
            if len(calls) > 1:
                raise OSError('simulated disk failure')
            refresh()
        self.worker.refresh = interrupted
        job = self.queue()
        with self.assertRaisesRegex(RuntimeError, 'configuration_recovery_required'):
            self.worker.run()
        self.assertTrue(job.exists())
        journal = self.worker.transactions / (self.identifier + '.json')
        self.assertEqual(json.loads(journal.read_bytes())['phase'], 'committed')
        self.assertFalse((self.admin / 'status' / (self.identifier + '.json')).exists())
        self.worker.refresh = refresh
        self.worker.restart = lambda: self.fail('Committed recovery must not restart or roll back')
        self.worker.run()
        self.assertEqual(self.status()['status'], 'succeeded')
        self.assertEqual(self.worker.load('export/config/manifest-input.json')['revision'], 5)
        self.assertFalse(job.exists())
        self.assertFalse(journal.exists())

    def test_prepared_recovery_validates_the_whole_snapshot_before_writing_any_file(self):
        original = (self.state / 'api/config/config.json').read_bytes()
        self.worker.restart = lambda: (_ for _ in ()).throw(OSError('simulated unavailable service'))
        self.queue()
        with self.assertRaisesRegex(RuntimeError, 'configuration_recovery_required'):
            self.worker.run()
        journal = self.worker.transactions / (self.identifier + '.json')
        transaction = json.loads(journal.read_bytes())
        self.assertEqual(transaction['phase'], 'prepared')
        broken = copy.deepcopy(transaction)
        broken['previous'][-1]['path'] = '../../outside.json'
        journal.write_bytes(worker_module.encoded(broken))
        changed = self.state / 'api/config/config.json'
        changed.write_bytes(b'not-yet-restored')
        with self.assertRaisesRegex(ValueError, 'invalid_transaction_path'):
            self.worker.recover(journal)
        self.assertEqual(changed.read_bytes(), b'not-yet-restored')
        journal.write_bytes(worker_module.encoded(transaction))
        self.worker.restart = lambda: None
        self.worker.run()
        self.assertEqual(changed.read_bytes(), original)
        self.assertEqual(self.status()['status'], 'failed')
        self.assertFalse(journal.exists())

    def test_witness_omitted_credentials_are_retained_only_for_the_same_provider(self):
        provider = self.witness()
        self.queue({'provider': 'mega', 'allowed_owners': ['e' * 64]})
        self.worker.run()
        saved = self.worker.load('storage/config/managed-storage.json')
        self.assertEqual(saved['provider'], provider)
        self.assertEqual(saved['allowed_owners'], ['e' * 64])
        self.assertNotIn('SENSITIVE', (self.admin / 'state.json').read_text())
        changed = validate_configuration('witness', {'provider': 's3', 'allowed_owners': [],
            's3_endpoint': 'https://s3.example', 's3_region': 'eu-1', 's3_bucket': 'bucket'})
        with self.assertRaisesRegex(ValueError, 'provider_credentials_required'):
            self.worker.storage_changes(changed)
        (self.state / 'compose.env').write_text('UNRELATED_ELO_STORAGE_IMAGE=elo-storage-mega\n')
        with self.assertRaisesRegex(ValueError, 'mega_adapter_unavailable'):
            self.worker.storage_changes({'provider': 'mega', 'allowed_owners': []})

    def test_disabling_storage_removes_credentials_but_preserves_service_identity(self):
        self.witness()
        self.queue({'provider': None, 'allowed_owners': []})
        self.worker.run()
        self.assertEqual(self.status()['status'], 'succeeded')
        self.assertFalse((self.state / 'storage/config/managed-storage.json').exists())
        self.assertEqual(self.worker.load('storage/config/config.json'), {'public_url': 'https://storage.example'})

    def test_worker_revalidates_every_request_and_does_not_change_config_on_invalid_input(self):
        original = (self.state / 'api/config/config.json').read_bytes()
        requests = [({'url': 'https://attacker.example'}, {}), ({}, {'created_at': True}),
                    ({}, {'created_at': int(time.time()) - 3601}), ({}, {'created_at': int(time.time()) + 60}),
                    ({}, {'v': True}), ({}, {'role': 'witness'}), ({'managed_provider': 'other'}, {})]
        for index, (configuration, wrapper) in enumerate(requests):
            with self.subTest(index=index):
                self.identifier = f'{index:032x}'
                self.queue(self.value | configuration, **wrapper)
                self.worker.run()
                self.assertEqual(self.status()['status'], 'failed')
                self.assertEqual((self.state / 'api/config/config.json').read_bytes(), original)
        self.body['storage'] = None
        self.write('export/config/manifest-input.json', self.body)
        with self.assertRaisesRegex(ValueError, 'storage_unavailable'):
            self.worker.api_changes(self.value)

    def test_job_bound_includes_wrapper_and_rejects_duplicate_keys(self):
        job = self.queue()
        content = job.read_bytes()
        job.write_bytes(content + b' ' * (worker_module.MAX_JOB - len(content)))
        self.worker.run()
        self.assertEqual(self.status()['status'], 'succeeded')
        self.identifier = 'b' * 32
        job = self.queue()
        content = job.read_bytes()
        job.write_bytes(content + b' ' * (worker_module.MAX_JOB + 1 - len(content)))
        self.worker.run()
        self.assertEqual(self.status()['status'], 'failed')
        for data in (b'{"v":1,"v":2}', b'{"created_at":NaN}', b'{"created_at":Infinity}'):
            with self.assertRaises(ValueError):
                worker_module.decode(data)

    def test_special_files_and_multiple_links_are_rejected_without_blocking(self):
        fifo = self.root / 'fifo'
        os.mkfifo(fifo)
        began = time.monotonic()
        with self.assertRaises(ValueError):
            worker_module.read_file(fifo)
        self.assertLess(time.monotonic() - began, 1)
        target = self.root / 'target'
        target.write_text('secret')
        link = self.root / 'link'
        link.symlink_to(target)
        with self.assertRaises(OSError):
            worker_module.read_file(link)
        link.unlink()
        os.link(target, link)
        with self.assertRaises(ValueError):
            worker_module.read_file(link)
        # A corrupt queue entry fails safely and does not read its external target.
        job = self.admin / 'queue' / (self.identifier + '.json')
        job.symlink_to(target)
        self.worker.run()
        self.assertEqual(self.status()['status'], 'failed')
        self.assertEqual(target.read_text(), 'secret')
        self.assertFalse(job.is_symlink())

    def test_queue_contention_keeps_request_pending(self):
        job = self.queue()
        with self.worker.queue_lock():
            with self.assertRaises(BlockingIOError):
                self.worker.run()
        self.assertTrue(job.exists())
        self.assertFalse((self.admin / 'status' / (self.identifier + '.json')).exists())

    def test_private_api_health_check_uses_only_the_trusted_loopback_instance(self):
        url = 'http://127.0.0.1:19900/spaces/v1/health'
        worker = worker_module.Worker(self.settings | {'api_health_url': url})
        commands, requests = [], []
        worker.compose = lambda arguments: commands.append(arguments)
        class Response:
            status = 200
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
        class Opener:
            def open(self, target, timeout):
                requests.append((target, timeout))
                return Response()
        with patch.object(worker_module.urllib.request, 'build_opener', return_value=Opener()):
            worker.restart()
        self.assertEqual(commands, [['restart', 'api']])
        self.assertEqual(requests, [(url, 2)])
        for wrong in ('https://example.com/health', 'http://127.0.0.1:19901/spaces/v1/health',
                      'http://127.0.0.1:19900/other'):
            with self.assertRaisesRegex(ValueError, 'invalid_health_endpoint'):
                worker_module.Worker(self.settings | {'api_health_url': wrong})

    def test_restart_requires_the_health_status_defined_by_each_service(self):
        class Response:
            def __init__(self, status):
                self.status = status
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass

        for role, status, accepted in (('api', 200, True), ('witness', 204, True),
                                       ('api', 204, False), ('witness', 200, False),
                                       ('api', 503, False), ('witness', 503, False)):
            with self.subTest(role=role, status=status):
                worker = worker_module.Worker(self.settings | {'role': role})
                commands, requests = [], []
                worker.compose = lambda arguments: commands.append(arguments)
                class Opener:
                    def open(self, target, timeout):
                        requests.append((target, timeout))
                        return Response(status)
                # One failed probe reaches the deadline without a real wait.
                with patch.object(worker_module.urllib.request, 'build_opener', return_value=Opener()), \
                        patch.object(worker_module.time, 'monotonic', side_effect=[0, 0, 31]), \
                        patch.object(worker_module.time, 'sleep'):
                    if accepted:
                        worker.restart()
                    else:
                        with self.assertRaisesRegex(ValueError, 'service_health_failed'):
                            worker.restart()
                service = 'api' if role == 'api' else 'storage'
                url = (worker.api_health_url if role == 'api'
                       else 'http://127.0.0.1:17846/health')
                self.assertEqual(commands, [['restart', service]])
                self.assertEqual(requests, [(url, 2)])


if __name__ == '__main__':
    unittest.main()
