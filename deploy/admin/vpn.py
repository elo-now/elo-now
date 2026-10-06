#!/usr/bin/env python3
"""Provision one independent WireGuard administration peer on an elo VPS.

Requires wireguard-tools and the existing elo_filter firewall. Receive only the
client public key and a distinct pre-shared key over stdin. The server private
key is generated on this host and is never returned to the caller.
"""
import argparse
import base64
from contextlib import contextmanager
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys

from apply import atomic, decode, read_file, sync_directory

INTERFACE = 'wg-elo-admin'
PORT = 51820
MARKER = '# elo administration WireGuard v1\n'
KEY_FILE = Path('/etc/wireguard/elo-admin.key')
CONFIG_FILE = Path('/etc/wireguard/wg-elo-admin.conf')
FIREWALL_FILE = Path('/etc/nftables.d/elo-z-admin-vpn.nft')
DROP_IN = Path('/etc/systemd/system/wg-quick@wg-elo-admin.service.d/10-elo-firewall.conf')
UNIT = 'wg-quick@' + INTERFACE + '.service'


def address(value, version):
    parsed = ipaddress.ip_address(value)
    networks = ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16') if version == 4 else ('fc00::/7',)
    if (parsed.version != version or getattr(parsed, 'scope_id', None)
            or not any(parsed in ipaddress.ip_network(n) for n in networks)):
        raise ValueError('private_host_address_required')
    return str(parsed)


def key(value):
    if not isinstance(value, str) or len(value) != 44:
        raise ValueError('invalid_wireguard_key')
    decoded = base64.b64decode(value, validate=True)
    if len(decoded) != 32 or decoded == bytes(32) or base64.b64encode(decoded).decode() != value:
        raise ValueError('invalid_wireguard_key')
    return value


def configuration(server4, server6, client4, client6, private_key, public_key, preshared_key):
    server4, client4 = address(server4, 4), address(client4, 4)
    server6, client6 = address(server6, 6), address(client6, 6)
    if server4 == client4 or server6 == client6:
        raise ValueError('overlapping_peer_addresses')
    return (MARKER + '[Interface]\n'
            f'Address = {server4}/32, {server6}/128\n'
            f'ListenPort = {PORT}\nPrivateKey = {key(private_key)}\n\n'
            '[Peer]\n' + f'PublicKey = {key(public_key)}\n'
            f'PresharedKey = {key(preshared_key)}\n'
            f'AllowedIPs = {client4}/32, {client6}/128\n').encode()


def firewall(client4, client6):
    client4, client6 = address(client4, 4), address(client6, 6)
    return (MARKER + 'table inet elo_admin_vpn {\n'
            '    chain protect {\n'
            '        type filter hook input priority -20; policy accept;\n'
            f'        ip saddr {client4} iifname != "{INTERFACE}" drop\n'
            f'        ip6 saddr {client6} iifname != "{INTERFACE}" drop\n'
            f'        iifname "{INTERFACE}" ip saddr != {client4} drop\n'
            f'        iifname "{INTERFACE}" ip6 saddr != {client6} drop\n'
            '    }\n}\n'
            'table inet elo_filter {\n    chain input {\n'
            f'        udp dport {PORT} accept comment "elo-admin-wireguard"\n'
            '    }\n}\n').encode()


def run(args, **kwargs):
    return subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=60, **kwargs).stdout


def protected_file(path):
    # read_file(uid=0) also accepts 0644; VPN keys and peer PSKs must be 0600.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as handle:
        info = os.fstat(handle.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600):
            raise ValueError('unsafe_vpn_file')
        content = handle.read(16385)
        if len(content) > 16384:
            raise ValueError('oversized_vpn_file')
        return content


def trusted_directory(path, create=False):
    # Do not chmod/chown an existing directory belonging to another setup.
    if create and not path.exists() and not path.is_symlink():
        trusted_directory(path.parent)
        path.mkdir(mode=0o700)
        sync_directory(path.parent)
    for ancestor in (path, *path.parents):
        info = ancestor.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022):
            raise ValueError('unsafe_vpn_directory')


@contextmanager
def installation_lock():
    fd = os.open(KEY_FILE.parent / '.elo-admin.lock',
                 os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600):
            raise ValueError('unsafe_vpn_lock')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def matching_file(path, expected):
    if path.exists() or path.is_symlink():
        if protected_file(path) != expected:
            raise ValueError('existing_vpn_configuration_differs')
        return True
    return False


def objects(arguments, kind):
    listing = decode(run(['nft', '--json', 'list', *arguments]))
    return [entry[kind] for entry in listing['nftables'] if kind in entry]


def match(left, value, operation='=='):
    return {'match': {'op': operation, 'left': left, 'right': value}}


def protection_rules(client4, client6):
    device = {'meta': {'key': 'iifname'}}
    result = []
    for protocol, client in (('ip', client4), ('ip6', client6)):
        source = {'payload': {'protocol': protocol, 'field': 'saddr'}}
        result.append([match(source, client), match(device, INTERFACE, '!='), {'drop': None}])
    for protocol, client in (('ip', client4), ('ip6', client6)):
        source = {'payload': {'protocol': protocol, 'field': 'saddr'}}
        result.append([match(device, INTERFACE), match(source, client, '!='), {'drop': None}])
    return result


def udp_rule():
    return [match({'payload': {'protocol': 'udp', 'field': 'dport'}}, PORT), {'accept': None}]


def validate_host_firewall():
    for name, hook in (('input', 'input'), ('forward', 'forward')):
        chains = objects(['chain', 'inet', 'elo_filter', name], 'chain')
        if (len(chains) != 1 or chains[0].get('type') != 'filter'
                or chains[0].get('hook') != hook or chains[0].get('policy') != 'drop'
                or chains[0].get('prio') != 0):
            raise ValueError('unexpected_host_firewall')


def verify_firewall(client4, client6):
    client4, client6 = address(client4, 4), address(client6, 6)
    validate_host_firewall()
    listing = decode(run(['nft', '--json', 'list', 'table', 'inet', 'elo_admin_vpn']))['nftables']
    chains = [item['chain'] for item in listing if 'chain' in item]
    rules = [item['rule'] for item in listing if 'rule' in item]
    if (len(chains) != 1 or chains[0].get('name') != 'protect'
            or chains[0].get('type') != 'filter' or chains[0].get('hook') != 'input'
            or chains[0].get('prio') != -20 or chains[0].get('policy') != 'accept'
            or any(set(item) - {'metainfo', 'table', 'chain', 'rule'} for item in listing)
            or [item.get('expr') for item in rules] != protection_rules(client4, client6)
            or any(item.get('chain') != 'protect' for item in rules)):
        raise ValueError('unexpected_vpn_firewall')
    inbound = objects(['chain', 'inet', 'elo_filter', 'input'], 'rule')
    owned = [item for item in inbound if item.get('comment') == 'elo-admin-wireguard']
    if len(owned) != 1 or owned[0].get('expr') != udp_rule():
        raise ValueError('missing_or_changed_wireguard_port_rule')


def service_protection(client4, client6):
    script = Path(__file__).absolute()
    trusted_directory(script.parent)
    read_file(script, uid=0)
    # The verifier must remain at this path after provisioning and after reboot.
    if any(character not in '/._-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
           for character in str(script)):
        raise ValueError('unsafe_installer_path')
    return (MARKER + '[Unit]\nRequires=nftables.service\nAfter=nftables.service\n\n'
            '[Service]\n' + f'ExecStartPre=/usr/bin/python3 {script} --verify-firewall '
            f'--client-ip {client4} --client-ipv6 {client6}\n').encode()


def install(args, peer):
    client4, client6 = address(args.client_ip, 4), address(args.client_ipv6, 6)
    validate_host_firewall()
    # Do not cause Requires= to start/flush an inactive host firewall during this
    # installation. On subsequent boots systemd loads it before the VPN.
    run(['systemctl', 'is-active', 'nftables.service'])
    # This host uses the managed nftables include. Do not claim reboot safety on
    # a machine where the persistent VPN rules would never be loaded.
    main_rules = read_file(Path('/etc/nftables.conf'), uid=0).decode()
    if 'include "/etc/nftables.d/*.nft"' not in main_rules.splitlines():
        raise ValueError('persistent_firewall_include_required')
    trusted_directory(KEY_FILE.parent, create=True)
    trusted_directory(FIREWALL_FILE.parent)
    trusted_directory(DROP_IN.parent, create=True)
    if any(path != DROP_IN for path in DROP_IN.parent.iterdir()):
        raise ValueError('unexpected_wireguard_unit_override')
    override = DROP_IN.parent.parent / UNIT
    if override.exists() or override.is_symlink():
        raise ValueError('unexpected_wireguard_unit_override')
    service = service_protection(client4, client6)
    with installation_lock():
        provision(args, peer, service)


def provision(args, peer, service):
    if KEY_FILE.exists() or KEY_FILE.is_symlink():
        private_key = key(protected_file(KEY_FILE).decode().strip())
    else:
        private_key = key(run(['wg', 'genkey']).decode().strip())
        atomic(KEY_FILE, (private_key + '\n').encode())
    config = configuration(args.server_ip, args.server_ipv6, args.client_ip,
                           args.client_ipv6, private_key, peer['public_key'], peer['preshared_key'])
    rules = firewall(args.client_ip, args.client_ipv6)
    present_config = matching_file(CONFIG_FILE, config)
    present_firewall = matching_file(FIREWALL_FILE, rules)
    present_service = matching_file(DROP_IN, service)
    interfaces = decode(run(['ip', '--json', 'link', 'show']))
    interface_exists = any(item['ifname'] == INTERFACE for item in interfaces)
    for line in run(['wg', 'show', 'all', 'listen-port']).decode().splitlines():
        name, port = line.split()
        if port == str(PORT) and name != INTERFACE:
            raise ValueError('wireguard_port_already_in_use')
    tables = objects(['tables'], 'table')
    table_exists = any(item.get('family') == 'inet' and item.get('name') == 'elo_admin_vpn'
                       for item in tables)
    if interface_exists and not (present_config and present_firewall and present_service):
        raise ValueError('wireguard_interface_already_exists')
    if table_exists and not present_firewall:
        raise ValueError('vpn_firewall_already_exists')
    if table_exists:
        verify_firewall(args.client_ip, args.client_ipv6)
        run(['nft', '--check', '--file', '/etc/nftables.conf'])
    else:
        # A matching file is a durable installation intent. If interrupted after
        # its write, retry can apply the same atomic nft transaction safely.
        if interface_exists:
            raise ValueError('active_vpn_without_firewall_requires_review')
        existing_rules = objects(['chain', 'inet', 'elo_filter', 'input'], 'rule')
        if any(item.get('comment') == 'elo-admin-wireguard' for item in existing_rules):
            raise ValueError('incomplete_live_firewall_requires_review')
        run(['nft', '--check', '--file', '-'], input=rules)
        if not present_firewall:
            atomic(FIREWALL_FILE, rules)
        run(['nft', '--check', '--file', '/etc/nftables.conf'])
        # Apply only this addition. Never flush/reload or replace an existing table.
        run(['nft', '--file', str(FIREWALL_FILE)])
        verify_firewall(args.client_ip, args.client_ipv6)
    if not present_service:
        atomic(DROP_IN, service)
    if not present_config:
        atomic(CONFIG_FILE, config)
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'enable', '--now', UNIT])
    run(['systemctl', 'is-active', UNIT])
    public_key = key(run(['wg', 'pubkey'], input=(private_key + '\n').encode()).decode().strip())
    if run(['wg', 'show', INTERFACE, 'public-key']).decode().strip() != public_key:
        raise ValueError('active_server_key_mismatch')
    # An already-active unit is not restarted by enable --now. Reject stale or
    # independently changed peers instead of reporting a successful installation.
    active = run(['wg', 'show', INTERFACE, 'dump']).decode().splitlines()
    expected_allowed = {f'{address(args.client_ip, 4)}/32', f'{address(args.client_ipv6, 6)}/128'}
    if (len(active) != 2 or active[0].split('\t')[2] != str(PORT)
            or active[1].split('\t')[0:2] != [peer['public_key'], peer['preshared_key']]
            or set(active[1].split('\t')[3].split(',')) != expected_allowed):
        raise ValueError('active_peer_configuration_mismatch')
    print(json.dumps({'interface': INTERFACE, 'public_key': public_key, 'port': PORT,
                      'server_ip': address(args.server_ip, 4), 'server_ipv6': address(args.server_ipv6, 6)}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verify-firewall', action='store_true')
    parser.add_argument('--server-ip')
    parser.add_argument('--server-ipv6')
    parser.add_argument('--client-ip', required=True)
    parser.add_argument('--client-ipv6', required=True)
    args = parser.parse_args()
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise ValueError('linux_root_required')
    if args.verify_firewall:
        verify_firewall(address(args.client_ip, 4), address(args.client_ipv6, 6))
        return
    if not args.server_ip or not args.server_ipv6:
        parser.error('--server-ip and --server-ipv6 are required for installation')
    for executable in ('wg', 'wg-quick', 'ip', 'nft', 'systemctl'):
        if not shutil.which(executable):
            raise ValueError('required_tool_missing')
    raw = sys.stdin.buffer.read(4097)
    if len(raw) > 4096:
        raise ValueError('invalid_peer')
    peer = decode(raw)
    if not isinstance(peer, dict) or set(peer) != {'public_key', 'preshared_key'}:
        raise ValueError('invalid_peer')
    key(peer['public_key'])
    key(peer['preshared_key'])
    for value, version in ((args.server_ip, 4), (args.server_ipv6, 6),
                           (args.client_ip, 4), (args.client_ipv6, 6)):
        address(value, version)
    install(args, peer)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        sys.exit('Administration VPN installation failed (' + type(error).__name__ + ').')
