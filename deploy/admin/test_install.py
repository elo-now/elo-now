"""Installer checks with synthetic credentials and no host mutations."""
import io
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).parent))
import install

HASH = '$2a$14$' + 'a' * 53
KEY = 'p' * 64
ORIGIN = 'https://hosting.example:9443'
CONFIG = '{\n\tadmin off\n}\n' + ORIGIN + ' {\n\trespond /health 204\n}\n'


class InstallerTests(unittest.TestCase):
    def test_proxy_has_one_authenticated_block_and_never_forwards_the_password(self):
        value = install.proxy_config(CONFIG, HASH, KEY, ORIGIN)
        self.assertIn('basic_auth {\n\t\t\tadmin ' + HASH, value)
        self.assertIn('header_up -Authorization', value)
        self.assertIn('header_up X-Elo-Admin-Proxy-Key ' + KEY, value)
        self.assertIn('max_size 32768', value)
        self.assertIn('response_header_timeout 10s', value)
        self.assertIn('respond /health 204', value)
        replacement = install.proxy_config(value, HASH, 'n' * 64, ORIGIN)
        self.assertEqual(replacement.count(install.BEGIN), 1)
        self.assertNotIn(KEY, replacement)
        self.assertEqual(install.proxy_config(replacement, HASH, 'n' * 64, ORIGIN), replacement)

    def test_proxy_rejects_different_or_multiple_sites_and_injected_credentials(self):
        for value in [CONFIG.replace(ORIGIN, 'https://other.example'), CONFIG + '\nhttps://other.example {\n}\n', CONFIG + install.BEGIN]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                install.proxy_config(value, HASH, KEY, ORIGIN)
        for hashed, key in [(HASH + '\nrespond 200', KEY), (HASH, KEY + '\n}')]:
            with self.assertRaises(ValueError):
                install.proxy_config(CONFIG, hashed, key, ORIGIN)

    def test_password_hash_is_offline_and_receives_the_password_only_on_stdin(self):
        password = 'synthetic-password-12345678'
        with patch.object(install, 'command', return_value=(HASH + '\n').encode()) as run:
            self.assertEqual(install.password_hash(password), HASH)
        args, kwargs = run.call_args
        self.assertNotIn(password, ' '.join(args[0]))
        self.assertEqual(kwargs['input'], (password + '\n').encode())
        self.assertIn('--network', args[0])
        self.assertEqual(args[0][args[0].index('--network') + 1], 'none')
        self.assertEqual(args[0][args[0].index('--cap-add') + 1], 'NET_BIND_SERVICE')
        self.assertIn('--read-only', args[0])
        self.assertIn('no-new-privileges:true', args[0])

    def test_directory_rejects_a_symlinked_ancestor_before_creating_anything(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / 'real').mkdir()
            (root / 'linked').symlink_to(root / 'real', target_is_directory=True)
            with self.assertRaises(ValueError):
                install.directory(root / 'linked' / 'child')
            self.assertFalse((root / 'real' / 'child').exists())

    def test_deployment_paths_require_root_owned_nonwritable_ancestors(self):
        safe = SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o755)
        with patch.object(Path, 'is_dir', return_value=True), patch.object(Path, 'lstat', return_value=safe):
            install.deployment_path(Path('/srv/elo-api-test'))
            for value in ('/srv/../etc', '/srv/elo state', 'relative'):
                with self.assertRaises(ValueError):
                    install.deployment_path(Path(value))
        for unsafe in [SimpleNamespace(st_uid=1000, st_mode=stat.S_IFDIR | 0o755),
                       SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o775),
                       SimpleNamespace(st_uid=0, st_mode=stat.S_IFLNK | 0o777)]:
            with patch.object(Path, 'is_dir', return_value=True), patch.object(Path, 'lstat', side_effect=lambda path=Path('/srv'), value=unsafe: value):
                with self.assertRaises(ValueError):
                    install.deployment_path(Path('/srv/elo-api-test'))

    def test_health_requires_the_expected_role_and_fails_closed(self):
        opener = Mock()
        opener.open.side_effect = lambda *a, **k: io.BytesIO(b'{"role":"api"}')
        with patch.object(install.urllib.request, 'build_opener', return_value=opener), patch.object(install.time, 'sleep'):
            install.wait_for_admin('api', KEY)
            self.assertEqual(opener.open.call_count, 1)
            with self.assertRaisesRegex(ValueError, 'admin_health_failed'):
                install.wait_for_admin('witness', KEY)
            self.assertEqual(opener.open.call_count, 21)
        opener.open.side_effect = lambda *a, **k: io.BytesIO(b'not-json')
        with patch.object(install.urllib.request, 'build_opener', return_value=opener), patch.object(install.time, 'sleep'):
            with self.assertRaisesRegex(ValueError, 'admin_health_failed'):
                install.wait_for_admin('api', KEY)

    def test_failed_proxy_update_restores_matching_backend_credentials(self):
        admin, caddy = Path('/srv/elo-admin'), Path('/srv/elo-api-test/proxy/config/Caddyfile')
        config_path, worker_path = admin / 'config.json', Path('/etc/elo-admin/worker.json')
        previous = {config_path: b'old-admin', worker_path: b'old-worker'}
        compose = ['docker', 'compose']

        def run(args, **kwargs):
            if 'validate' in args:
                raise ValueError('synthetic_invalid_config')
            return b''

        with patch.object(install, 'read_file', side_effect=lambda path: previous[path]), \
                patch.object(install, 'atomic') as write, patch.object(install, 'command', side_effect=run) as command, \
                patch.object(install, 'wait_for_admin'):
            with self.assertRaisesRegex(ValueError, '^installation_rolled_back$'):
                install.activate(admin, caddy, b'old-proxy', b'new-proxy', compose, 'api', KEY, b'new-admin', b'new-worker')
        self.assertIn(((caddy, b'old-proxy', 21004, 21004), {}), write.call_args_list)
        self.assertIn(((config_path, b'old-admin', 0, 21010), {'mode': 0o640}), write.call_args_list)
        self.assertIn(((worker_path, b'old-worker', 0, 0), {'mode': 0o600}), write.call_args_list)
        self.assertEqual(command.call_args_list[-1].args[0], compose + ['restart', 'proxy'])

    def test_initial_backend_failure_removes_credentials_and_disables_admin_only(self):
        admin, caddy = Path('/srv/elo-admin'), Path('/srv/elo-api-test/proxy/config/Caddyfile')
        with patch.object(install, 'read_file', side_effect=FileNotFoundError), \
                patch.object(install, 'atomic') as write, patch.object(install, 'command') as command, \
                patch.object(install, 'wait_for_admin', side_effect=ValueError('synthetic_health_failure')), \
                patch.object(Path, 'unlink') as unlink:
            with self.assertRaisesRegex(ValueError, '^installation_rolled_back$'):
                install.activate(admin, caddy, b'old-proxy', b'new-proxy', ['docker', 'compose'], 'api', KEY, b'new-admin', b'new-worker')
        self.assertEqual(unlink.call_count, 2)
        self.assertNotIn(caddy, [call.args[0] for call in write.call_args_list])
        self.assertFalse(any('docker' in call.args[0] for call in command.call_args_list))
        self.assertEqual(command.call_args_list[-1].args[0], ['systemctl', 'disable', '--now', 'elo-admin.service', 'elo-admin-apply.path', 'elo-admin-apply.timer'])

    def test_systemd_separates_network_server_from_privileged_worker(self):
        units = install.units(Path('/srv/elo-api-test'))
        server, worker = units['elo-admin.service'], units['elo-admin-apply.service']
        self.assertIn('User=elo-admin', server)
        self.assertIn('CapabilityBoundingSet=\n', server)
        self.assertIn('ReadWritePaths=/srv/elo-admin/queue', server)
        self.assertNotIn('/srv/elo-api-test', server)
        for content in (server, worker):
            self.assertIn('NoNewPrivileges=yes', content)
            self.assertIn('ProtectSystem=strict', content)
            self.assertIn('ProtectHome=yes', content)
            self.assertIn('IPAddressDeny=any', content)
            self.assertIn('IPAddressAllow=localhost', content)
        self.assertIn('RestrictAddressFamilies=AF_UNIX AF_INET', worker)
        self.assertIn('ReadWritePaths=/srv/elo-api-test /srv/elo-admin /run/elo-admin-apply.lock', worker)


if __name__ == '__main__':
    unittest.main()
