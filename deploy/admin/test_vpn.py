"""Administration VPN isolation and generated configuration regression checks."""
import base64
from contextlib import ExitStack
import copy
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))
import vpn

KEY = base64.b64encode(bytes(range(32))).decode()
PUBLIC = base64.b64encode(bytes(range(1, 33))).decode()
PSK = base64.b64encode(bytes(range(2, 34))).decode()
CLIENT4, CLIENT6 = '10.77.36.10', 'fd77:36:9b17::10'
ARGS = SimpleNamespace(server_ip='10.77.36.1', server_ipv6='fd77:36:9b17::1',
                       client_ip=CLIENT4, client_ipv6=CLIENT6)
PEER = {'public_key': PUBLIC, 'preshared_key': PSK}


class FakeHost:
    """Model live nft/WireGuard state without privileged host operations."""
    def __init__(self):
        self.table = False
        self.interface = False
        self.udp = False
        self.applies = 0
        self.starts = 0
        self.commands = []
        self.fail_apply = False
        self.fail_enable = False
        self.other_listener = False
        self.protection = vpn.protection_rules(CLIENT4, CLIENT6)
        self.priority = -20
        self.forward_policy = 'drop'

    def run(self, args, **kwargs):
        self.commands.append(args)
        if args == ['wg', 'genkey']:
            return (KEY + '\n').encode()
        if args == ['wg', 'pubkey']:
            return (PUBLIC + '\n').encode()
        if args == ['wg', 'show', 'all', 'listen-port']:
            return b'wg-unrelated\t51820\n' if self.other_listener else b''
        if args == ['wg', 'show', vpn.INTERFACE, 'public-key']:
            return (PUBLIC + '\n').encode()
        if args == ['wg', 'show', vpn.INTERFACE, 'dump']:
            return (f'{KEY}\t{PUBLIC}\t51820\toff\n'
                    f'{PUBLIC}\t{PSK}\t(none)\t{CLIENT4}/32,{CLIENT6}/128\t0\t0\t0\t0\n').encode()
        if args == ['ip', '--json', 'link', 'show']:
            return json.dumps([{'ifname': vpn.INTERFACE}] if self.interface else []).encode()
        if args[:3] == ['nft', '--json', 'list']:
            target = args[3:]
            if target == ['tables']:
                entries = [{'table': {'family': 'inet', 'name': 'elo_admin_vpn'}}] if self.table else []
            elif target == ['table', 'inet', 'elo_admin_vpn']:
                if not self.table:
                    raise RuntimeError('table_absent')
                entries = [{'chain': {'name': 'protect', 'type': 'filter', 'hook': 'input',
                                      'prio': self.priority, 'policy': 'accept'}}]
                entries += [{'rule': {'chain': 'protect', 'expr': item}} for item in self.protection]
            elif target[:3] == ['chain', 'inet', 'elo_filter']:
                name = target[3]
                entries = [{'chain': {'name': name, 'type': 'filter', 'hook': name, 'prio': 0,
                                      'policy': self.forward_policy if name == 'forward' else 'drop'}}]
                if name == 'input' and self.udp:
                    entries += [{'rule': {'comment': 'elo-admin-wireguard', 'expr': vpn.udp_rule()}}]
            else:
                raise AssertionError(args)
            return json.dumps({'nftables': entries}).encode()
        if args[:2] == ['nft', '--check']:
            return b''
        if args == ['nft', '--file', str(vpn.FIREWALL_FILE)]:
            if self.fail_apply:
                raise RuntimeError('interrupted_before_nft_apply')
            if self.table:
                raise AssertionError('must_not_apply_twice')
            self.table, self.udp = True, True
            self.applies += 1
            return b''
        if args == ['systemctl', 'enable', '--now', vpn.UNIT]:
            if not (self.table and self.udp and vpn.DROP_IN.exists() and vpn.CONFIG_FILE.exists()):
                raise AssertionError('started_before_protection')
            self.interface = True
            self.starts += 1
            if self.fail_enable:
                raise RuntimeError('interrupted_after_enable')
            return b''
        if args in [['systemctl', 'daemon-reload'], ['systemctl', 'is-active', vpn.UNIT]]:
            return b'active\n'
        raise AssertionError(args)


class VPNTests(unittest.TestCase):
    def test_only_exact_private_host_addresses_are_accepted(self):
        self.assertEqual(vpn.address('10.77.36.10', 4), '10.77.36.10')
        self.assertEqual(vpn.address('fd77:36:9b17::10', 6), 'fd77:36:9b17::10')
        for value, version in [('0.0.0.0', 4), ('127.0.0.1', 4), ('169.254.1.1', 4),
                               ('8.8.8.8', 4), ('10.0.0.0/8', 4), ('::1', 6),
                               ('::', 6), ('fe80::1', 6), ('ff02::1', 6),
                               ('2001:db8::1', 6), ('fd77:36:9b17::10%eth0', 6),
                               ('fd77:36:9b17::10%\nPostUp=true', 6),
                               ('10.77.36.10\nSaveConfig=true', 4)]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                vpn.address(value, version)

    def test_keys_are_canonical_nonzero_base64_and_cannot_inject_settings(self):
        self.assertEqual(vpn.key(KEY), KEY)
        for value in [KEY + '\nPostUp=true', '', 'x' * 44, base64.b64encode(bytes(32)).decode()]:
            with self.assertRaises(ValueError):
                vpn.key(value)

    def test_peer_is_limited_to_its_own_addresses_without_forwarding_hooks(self):
        result = vpn.configuration('10.77.36.1', 'fd77:36:9b17::1', '10.77.36.10',
                                   'fd77:36:9b17::10', KEY, KEY, KEY).decode()
        self.assertIn('AllowedIPs = 10.77.36.10/32, fd77:36:9b17::10/128', result)
        for forbidden in ['0.0.0.0/0', '::/0', 'PostUp', 'SaveConfig', 'Endpoint', 'DNS']:
            self.assertNotIn(forbidden, result)
        with self.assertRaises(ValueError):
            vpn.configuration('10.77.36.10', 'fd77:36:9b17::1', '10.77.36.10',
                              'fd77:36:9b17::10', KEY, KEY, KEY)

    def test_firewall_rejects_spoofed_sources_before_existing_public_accepts(self):
        result = vpn.firewall('10.77.36.10', 'fd77:36:9b17::10').decode()
        self.assertIn('hook input priority -20', result)
        self.assertIn('ip saddr 10.77.36.10 iifname != "wg-elo-admin" drop', result)
        self.assertIn('ip6 saddr fd77:36:9b17::10 iifname != "wg-elo-admin" drop', result)
        self.assertIn('iifname "wg-elo-admin" ip saddr != 10.77.36.10 drop', result)
        self.assertIn('udp dport 51820 accept', result)
        for forbidden in ['flush', 'masquerade', 'hook forward', 'tcp dport', '0.0.0.0/0']:
            self.assertNotIn(forbidden, result)

    def test_secret_reads_require_root_0600_single_regular_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'key'
            path.write_text(KEY)
            real_fstat = os.fstat
            def as_root(fd):
                fields = list(real_fstat(fd))
                fields[4] = 0
                return os.stat_result(fields)
            with patch.object(vpn.os, 'fstat', side_effect=as_root):
                for mode in (0o644, 0o640, 0o660, 0o700):
                    path.chmod(mode)
                    with self.subTest(mode=oct(mode)), self.assertRaises(ValueError):
                        vpn.protected_file(path)
                path.chmod(0o600)
                self.assertEqual(vpn.protected_file(path), KEY.encode())
                link = path.with_name('link')
                link.symlink_to(path)
                with self.assertRaises(OSError):
                    vpn.protected_file(link)
                link.unlink()
                os.link(path, link)
                with self.assertRaises(ValueError):
                    vpn.protected_file(path)
            with patch.object(vpn.os, 'fstat', return_value=SimpleNamespace(
                    st_mode=stat.S_IFREG | 0o600, st_uid=123, st_nlink=1)):
                with self.assertRaises(ValueError):
                    vpn.protected_file(path)
            with patch.object(vpn.os, 'fstat', return_value=SimpleNamespace(
                    st_mode=stat.S_IFREG | 0o4600, st_uid=0, st_nlink=1)):
                with self.assertRaises(ValueError):
                    vpn.protected_file(path)

    def test_verifier_rejects_removed_changed_or_extra_rules_and_hook(self):
        host = FakeHost()
        host.table, host.udp = True, True
        with patch.object(vpn, 'run', side_effect=host.run):
            vpn.verify_firewall(CLIENT4, CLIENT6)
            originals = copy.deepcopy(host.protection)
            bad_rules = [originals[:-1], originals + [[{'accept': None}]],
                         [[{'accept': None}], *originals[1:]], list(reversed(originals))]
            for rules in bad_rules:
                host.protection = rules
                with self.assertRaises(ValueError):
                    vpn.verify_firewall(CLIENT4, CLIENT6)
            host.protection = originals
            host.priority = 20
            with self.assertRaises(ValueError):
                vpn.verify_firewall(CLIENT4, CLIENT6)
            host.priority = -20
            host.udp = False
            with self.assertRaises(ValueError):
                vpn.verify_firewall(CLIENT4, CLIENT6)
            host.udp = True
            host.forward_policy = 'accept'
            with self.assertRaises(ValueError):
                vpn.verify_firewall(CLIENT4, CLIENT6)

    def test_service_requires_firewall_and_strict_verification_before_start(self):
        with patch.object(vpn, 'trusted_directory'), patch.object(vpn, 'read_file'):
            unit = vpn.service_protection(CLIENT4, CLIENT6).decode()
        self.assertIn('Requires=nftables.service\nAfter=nftables.service', unit)
        self.assertIn('ExecStartPre=/usr/bin/python3 ', unit)
        self.assertIn(f'--verify-firewall --client-ip {CLIENT4} --client-ipv6 {CLIENT6}', unit)


class ProvisioningTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        for constant in ('KEY_FILE', 'CONFIG_FILE', 'FIREWALL_FILE', 'DROP_IN'):
            self.stack.enter_context(patch.object(vpn, constant, root / constant.lower()))
        self.stack.enter_context(patch.object(vpn, 'protected_file', side_effect=Path.read_bytes))
        self.stack.enter_context(patch.object(vpn, 'atomic', side_effect=self.write))
        self.stack.enter_context(patch('builtins.print'))
        self.host = FakeHost()
        self.stack.enter_context(patch.object(vpn, 'run', side_effect=self.host.run))

    @staticmethod
    def write(path, data, **kwargs):
        path.write_bytes(data)
        path.chmod(0o600)

    def provision(self):
        vpn.provision(ARGS, PEER, b'# test strict verifier\n')

    def test_installation_and_idempotent_retry_do_not_reload_existing_firewall(self):
        self.provision()
        self.provision()
        self.assertEqual(self.host.applies, 1)
        self.assertTrue(self.host.interface)
        self.assertFalse(any('flush' in item for command in self.host.commands for item in command))
        self.assertIn(['nft', '--check', '--file', '/etc/nftables.conf'], self.host.commands)

    def test_each_durable_write_can_be_interrupted_and_safely_resumed(self):
        for constant in ('KEY_FILE', 'FIREWALL_FILE', 'DROP_IN', 'CONFIG_FILE'):
            with self.subTest(point=constant):
                for name in ('KEY_FILE', 'CONFIG_FILE', 'FIREWALL_FILE', 'DROP_IN'):
                    getattr(vpn, name).unlink(missing_ok=True)
                self.host = FakeHost()
                with patch.object(vpn, 'run', side_effect=self.host.run):
                    interrupted = getattr(vpn, constant)
                    def write_then_interrupt(path, data, **kwargs):
                        self.write(path, data)
                        if path == interrupted:
                            raise RuntimeError('simulated_power_loss')
                    with patch.object(vpn, 'atomic', side_effect=write_then_interrupt):
                        with self.assertRaises(RuntimeError):
                            self.provision()
                    self.assertFalse(self.host.interface)
                    self.provision()
                    self.assertTrue(self.host.interface)
                    self.assertEqual(self.host.applies, 1)

    def test_interruption_before_nft_apply_leaves_retryable_protection_intent(self):
        self.host.fail_apply = True
        with self.assertRaises(RuntimeError):
            self.provision()
        self.assertTrue(vpn.FIREWALL_FILE.exists())
        self.assertFalse(vpn.CONFIG_FILE.exists())
        self.host.fail_apply = False
        self.provision()
        self.assertTrue(self.host.interface)

    def test_interruption_after_enable_is_checked_on_retry(self):
        self.host.fail_enable = True
        with self.assertRaises(RuntimeError):
            self.provision()
        self.host.fail_enable = False
        self.provision()
        self.assertEqual(self.host.applies, 1)

    def test_foreign_interface_table_and_port_are_not_taken_over(self):
        for attribute in ('interface', 'table', 'other_listener'):
            with self.subTest(conflict=attribute):
                setattr(self.host, attribute, True)
                with self.assertRaises(ValueError):
                    self.provision()
                self.assertEqual(self.host.applies, 0)
                self.assertEqual(self.host.starts, 0)
                self.assertFalse(vpn.CONFIG_FILE.exists())
                self.assertFalse(vpn.FIREWALL_FILE.exists())
                setattr(self.host, attribute, False)

    def test_changed_disk_or_live_configuration_is_never_overwritten(self):
        self.provision()
        original = vpn.CONFIG_FILE.read_bytes()
        vpn.CONFIG_FILE.write_bytes(original + b'# external change\n')
        with self.assertRaises(ValueError):
            self.provision()
        self.assertEqual(vpn.CONFIG_FILE.read_bytes(), original + b'# external change\n')
        vpn.CONFIG_FILE.write_bytes(original)
        self.host.protection.pop()
        with self.assertRaises(ValueError):
            self.provision()
        self.assertEqual(self.host.applies, 1)
        self.assertEqual(self.host.starts, 1)

    def test_active_interface_without_protection_is_not_reported_as_success(self):
        self.provision()
        self.host.table = False
        with self.assertRaises(ValueError):
            self.provision()
        self.assertEqual(self.host.starts, 1)


if __name__ == '__main__':
    unittest.main()
