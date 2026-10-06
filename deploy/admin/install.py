#!/usr/bin/env python3
"""Install the protected hosting administrator on an initialized Linux host.

Read the initial HTTPS password and internal proxy credential from JSON on stdin.
Only the API or storage service can be restarted by configuration changes.
"""
import argparse
import json
import os
from pathlib import Path
import pwd
import grp
import re
import stat
import subprocess
import sys
import time
import urllib.request

from apply import atomic, encoded, read_file
from schema import origin

FILES = ('server.py', 'schema.py', 'apply.py', 'static/index.html', 'static/app.js',
         'static/style.css', 'static/en.json')
BEGIN, END = '\t# BEGIN ELO ADMIN\n', '\t# END ELO ADMIN\n'


def command(args, **kwargs):
    return subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=120, **kwargs).stdout


def directory(path, uid=0, gid=0, mode=0o700):
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError('unsafe_directory')
    path.mkdir(parents=True, exist_ok=True)
    if path.is_symlink() or not path.is_dir():
        raise ValueError('unsafe_directory')
    os.chown(path, uid, gid)
    os.chmod(path, mode)


def deployment_path(path):
    if (not path.is_absolute() or not path.is_dir() or '..' in path.parts
            or not re.fullmatch(r'/[A-Za-z0-9_./-]+', str(path))):
        raise ValueError('unsafe_deployment_path')
    for parent in (path, *path.parents):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('unsafe_deployment_path')


def password_hash(password):
    # The upstream executable carries NET_BIND_SERVICE as a file capability,
    # including for this offline command; its bounding set must permit loading it.
    return command(['docker', 'run', '--rm', '-i', '--pull', 'never', '--network', 'none',
                    '--read-only', '--cap-drop', 'ALL', '--cap-add', 'NET_BIND_SERVICE',
                    '--security-opt', 'no-new-privileges:true', '--pids-limit', '32',
                    '--memory', '128m', '--memory-swap', '128m', '--ulimit', 'core=0',
                    'caddy:2.11.7-alpine', 'caddy', 'hash-password'],
                   input=(password + '\n').encode()).decode().strip()


def proxy_config(previous, password_hash, proxy_key, public_origin):
    if not re.fullmatch(r'\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}', password_hash):
        raise ValueError('invalid_password_hash')
    if not re.fullmatch(r'[A-Za-z0-9_-]{32,256}', proxy_key):
        raise ValueError('invalid_proxy_key')
    sites = re.findall(r'(?m)^([^\s{}#][^{}\n]*?)\s+\{\s*$', previous)
    if sites != [public_origin]:
        raise ValueError('unexpected_proxy_site')
    if previous.count(BEGIN) != previous.count(END) or previous.count(BEGIN) > 1:
        raise ValueError('invalid_admin_proxy_block')
    if BEGIN in previous:
        start = previous.index(BEGIN)
        previous = previous[:start] + previous[previous.index(END, start) + len(END):]
    # The generated deployment has one HTTPS site and ends with its closing brace.
    position = previous.rfind('\n}')
    if position < 0:
        raise ValueError('invalid_proxy_config')
    block = BEGIN + f'''\tredir /admin /admin/ 308
\thandle /admin/* {{
\t\tbasic_auth {{
\t\t\tadmin {password_hash}
\t\t}}
\t\trequest_body {{
\t\t\tmax_size 32768
\t\t}}
\t\treverse_proxy 127.0.0.1:17910 {{
\t\t\theader_up -Authorization
\t\t\theader_up X-Elo-Admin-Proxy-Key {proxy_key}
\t\t\ttransport http {{
\t\t\t\tdial_timeout 2s
\t\t\t\tresponse_header_timeout 10s
\t\t\t}}
\t\t}}
\t}}
''' + END
    return previous[:position].rstrip('\n') + '\n' + block + previous[position:]


def units(state):
    return {
        'elo-admin.service': '''[Unit]
Description=elo hosting administration
After=network.target
[Service]
User=elo-admin
Group=elo-admin
ExecStart=/usr/bin/python3 /opt/elo-admin/server.py --root /srv/elo-admin --static /opt/elo-admin/static --port 17910
Environment=PYTHONDONTWRITEBYTECODE=1
UMask=0077
Restart=on-failure
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictAddressFamilies=AF_INET
IPAddressDeny=any
IPAddressAllow=localhost
ReadWritePaths=/srv/elo-admin/queue
CapabilityBoundingSet=
TasksMax=16
MemoryMax=128M
[Install]
WantedBy=multi-user.target
''',
        'elo-admin-apply.service': f'''[Unit]
Description=Apply a validated elo hosting configuration
After=docker.service
Requires=docker.service
[Service]
Type=oneshot
User=root
Group=root
ExecStart=/usr/bin/python3 /opt/elo-admin/apply.py --config /etc/elo-admin/worker.json
Environment=PYTHONDONTWRITEBYTECODE=1
UMask=0077
TimeoutStartSec=5min
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths={state} /srv/elo-admin /run/elo-admin-apply.lock
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictAddressFamilies=AF_UNIX AF_INET
IPAddressDeny=any
IPAddressAllow=localhost
CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER
TasksMax=64
MemoryMax=256M
''',
        'elo-admin-apply.path': '''[Unit]
Description=Watch for elo hosting configuration changes
[Path]
PathChanged=/srv/elo-admin/queue
Unit=elo-admin-apply.service
[Install]
WantedBy=multi-user.target
''',
        'elo-admin-apply.timer': '''[Unit]
Description=Recover interrupted elo configuration changes
[Timer]
OnBootSec=1min
OnUnitInactiveSec=1min
Unit=elo-admin-apply.service
[Install]
WantedBy=timers.target
''',
        'elo-admin.conf': 'f /run/elo-admin-apply.lock 0600 root root -\n',
    }


def wait_for_admin(role, proxy_key):
    request = urllib.request.Request('http://127.0.0.1:17910/admin/api/state',
              headers={'X-Elo-Admin-Proxy-Key': proxy_key})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for _ in range(20):
        try:
            with opener.open(request, timeout=2) as reply:
                value = json.load(reply)
                if isinstance(value, dict) and value.get('role') == role:
                    return
        except (OSError, ValueError):
            pass
        time.sleep(.2)
    raise ValueError('admin_health_failed')



def activate(admin, caddy, before, updated, compose, role, proxy_key, config, worker):
    config_path, worker_path = admin / 'config.json', Path('/etc/elo-admin/worker.json')
    previous = {}
    for path in (config_path, worker_path):
        try:
            previous[path] = read_file(path)
        except FileNotFoundError:
            previous[path] = None
    proxy_changed = False
    try:
        atomic(config_path, config, 0, 21010, mode=0o640)
        atomic(worker_path, worker)
        command(['python3', '/opt/elo-admin/apply.py', '--config', str(worker_path), '--refresh-state'])
        command(['systemctl', 'daemon-reload'])
        command(['systemctl', 'enable', '--now', 'elo-admin.service', 'elo-admin-apply.path', 'elo-admin-apply.timer'])
        command(['systemctl', 'restart', 'elo-admin.service'])
        wait_for_admin(role, proxy_key)
        atomic(admin / 'install/Caddyfile.previous', before)
        atomic(caddy, updated, 21004, 21004)
        proxy_changed = True
        command(compose + ['exec', '-T', 'proxy', 'caddy', 'validate', '--config', '/etc/caddy/Caddyfile', '--adapter', 'caddyfile'])
        command(compose + ['restart', 'proxy'])
    except Exception:
        # A changed proxy key must roll back with Caddy, or reinstall failures
        # permanently disconnect the old HTTPS endpoint from its backend.
        try:
            if proxy_changed:
                atomic(caddy, before, 21004, 21004)
            for path, data in previous.items():
                if data is None:
                    path.unlink(missing_ok=True)
                else:
                    atomic(path, data, 0, 21010 if path == config_path else 0,
                           mode=0o640 if path == config_path else 0o600)
            if previous[config_path] is not None:
                command(['systemctl', 'restart', 'elo-admin.service'])
            else:
                command(['systemctl', 'disable', '--now', 'elo-admin.service', 'elo-admin-apply.path', 'elo-admin-apply.timer'])
            if proxy_changed:
                command(compose + ['restart', 'proxy'])
        except Exception:
            raise ValueError('installation_rollback_failed') from None
        raise ValueError('installation_rolled_back') from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--role', choices=('api', 'witness'), required=True)
    parser.add_argument('--origin', required=True)
    parser.add_argument('--related-origin', required=True)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--api-port', type=int, choices=(18900, 19900), default=18900)
    args = parser.parse_args()
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise ValueError('linux_root_required')
    if args.role != 'api' and args.api_port != 18900:
        raise ValueError('api_port_requires_api_role')
    for path in (args.state, args.bundle):
        deployment_path(path)
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', args.version):
        raise ValueError('invalid_version')
    public_origin, related_origin = origin(args.origin), origin(args.related_origin)
    # These files direct root's Docker operations or execute inside the worker.
    for name in (('export.py', 'init.py') if args.role == 'api' else ()) + ('compose.' + args.role + '.yaml',):
        read_file(args.bundle / name, uid=0)
    read_file(args.state / 'compose.env', uid=0)
    if read_file(args.state / 'role') != (args.role + '\n').encode():
        raise ValueError('role_mismatch')
    payload = sys.stdin.buffer.read(16385)
    if len(payload) > 16384:
        raise ValueError('invalid_credentials')
    secret = json.loads(payload)
    if not isinstance(secret, dict) or set(secret) != {'password', 'proxy_key'}:
        raise ValueError('invalid_credentials')
    if not re.fullmatch(r'[A-Za-z0-9_-]{24,128}', secret['password']):
        raise ValueError('invalid_password')
    if not re.fullmatch(r'[A-Za-z0-9_-]{32,256}', secret['proxy_key']):
        raise ValueError('invalid_proxy_key')
    # Password is read from stdin by Caddy, never passed in argv or emitted in logs.
    hashed = password_hash(secret['password'])
    caddy = args.state / 'proxy/config/Caddyfile'
    before = read_file(caddy)
    updated = proxy_config(before.decode(), hashed, secret['proxy_key'], public_origin).encode()
    try:
        group = grp.getgrgid(21010)
        if group.gr_name != 'elo-admin':
            raise ValueError('admin_gid_taken')
    except KeyError:
        command(['groupadd', '--system', '--gid', '21010', 'elo-admin'])
    try:
        user = pwd.getpwuid(21010)
        if user.pw_name != 'elo-admin' or user.pw_gid != 21010:
            raise ValueError('admin_uid_taken')
    except KeyError:
        command(['useradd', '--system', '--uid', '21010', '--gid', '21010', '--no-create-home',
                 '--home-dir', '/nonexistent', '--shell', '/usr/sbin/nologin', 'elo-admin'])
    if set(os.getgrouplist('elo-admin', 21010)) != {21010}:
        raise ValueError('admin_supplementary_groups')
    source, target = Path(__file__).resolve().parent, Path('/opt/elo-admin')
    directory(target, mode=0o755)
    directory(target / 'static', mode=0o755)
    for name in FILES:
        atomic(target / name, read_file(source / name), mode=0o644)
    admin = Path('/srv/elo-admin')
    directory(admin, gid=21010, mode=0o750)
    directory(admin / 'queue', 21010, 21010)
    directory(admin / 'status', gid=21010, mode=0o750)
    directory(admin / 'transactions')
    directory(admin / 'install')
    directory(Path('/etc/elo-admin'))
    config = {'role': args.role, 'public_origin': public_origin,
              'proxy_key': secret['proxy_key'], 'related_admin_url': related_origin + '/admin/'}
    worker = {'role': args.role, 'state_root': str(args.state), 'admin_root': str(admin),
              'container_bundle': str(args.bundle), 'version': args.version}
    if args.role == 'api':
        worker['api_health_url'] = f'http://127.0.0.1:{args.api_port}/spaces/v1/health'
    for name, content in units(args.state).items():
        destination = Path('/etc/tmpfiles.d' if name.endswith('.conf') else '/etc/systemd/system') / name
        atomic(destination, content.encode(), mode=0o644)
    command(['systemd-tmpfiles', '--create', '/etc/tmpfiles.d/elo-admin.conf'])
    compose = ['docker', 'compose', '--env-file', str(args.state / 'compose.env'),
               '-f', str(args.bundle / ('compose.' + args.role + '.yaml'))]
    activate(admin, caddy, before, updated, compose, args.role, secret['proxy_key'],
             encoded(config), encoded(worker))
    print(json.dumps({'role': args.role, 'admin_url': public_origin + '/admin/', 'installed': True}))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # Never echo subprocess output, configuration values or secrets.
        sys.exit('Administration installation failed (' + type(error).__name__ + ').')
