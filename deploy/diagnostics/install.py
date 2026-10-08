#!/usr/bin/env python3
"""Install live beta diagnostics on an existing native elo admin/API host."""
import argparse
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import subprocess

BEGIN = '\t# BEGIN ELO DIAGNOSTICS\n'
END = '\t# END ELO DIAGNOSTICS\n'


def proxy_config(previous):
    if previous.count(BEGIN) != previous.count(END) or previous.count(BEGIN) > 1:
        raise ValueError('Unexpected diagnostic proxy configuration')
    if BEGIN in previous:
        start = previous.index(BEGIN)
        previous = previous[:start] + previous[previous.index(END, start) + len(END):]
    position = previous.rfind('\n}')
    if position < 0:
        raise ValueError('Missing HTTPS site')
    block = BEGIN + '''\t@elo_diagnostics path /diagnostics/v1/errors
\thandle @elo_diagnostics {
\t\troute {
\t\t\t@not_post not method POST
\t\t\trespond @not_post 405
\t\t\trequest_body {
\t\t\t\tmax_size 16384
\t\t\t}
\t\t\treverse_proxy 127.0.0.1:17930 {
\t\t\t\theader_up -Authorization
\t\t\t\theader_up -Cookie
\t\t\t\theader_up -X-Elo-Admin-Proxy-Key
\t\t\t\ttransport http {
\t\t\t\t\tdial_timeout 2s
\t\t\t\t\tresponse_header_timeout 8s
\t\t\t\t}
\t\t\t}
\t\t}
\t}
''' + END
    return previous[:position].rstrip('\n') + '\n' + block + previous[position:]


def run(args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--proxy-config', type=Path, required=True)
    parser.add_argument('--proxy-container', required=True)
    parser.add_argument('--admin-source', type=Path, required=True)
    args = parser.parse_args()
    if os.getuid() != 0:
        parser.error('Root is required for installation')
    if not re.fullmatch(r'[a-z0-9-]+', args.proxy_container):
        parser.error('Invalid container name')
    os.umask(0o077)
    source = Path(__file__).parent
    rollback = Path('/var/lib/elo-diagnostics-deploy')
    if rollback.exists():
        raise ValueError('Resolve the existing deployment backup before redeploying')
    admin = pwd.getpwnam('elo-admin')
    try:
        service = pwd.getpwnam('elo-diagnostics')
    except KeyError:
        run(['useradd', '--system', '--user-group', '--no-create-home', '--home-dir', '/nonexistent', '--shell', '/usr/sbin/nologin', 'elo-diagnostics'])
        service = pwd.getpwnam('elo-diagnostics')
    root = Path('/srv/elo-diagnostics')
    root.mkdir(mode=0o700, exist_ok=True)
    os.chown(root, service.pw_uid, service.pw_gid)
    key_path = root / 'read-key'
    if not key_path.exists():
        key_path.write_text(secrets.token_urlsafe(32) + '\n')
    key = key_path.read_text().strip()
    if not re.fullmatch(r'[A-Za-z0-9_-]{32,128}', key):
        raise ValueError('Invalid existing read credential')
    os.chmod(key_path, 0o600); os.chown(key_path, service.pw_uid, service.pw_gid)
    destination = Path('/opt/elo-diagnostics')
    destination.mkdir(mode=0o755, exist_ok=True)
    os.chmod(destination, 0o755)
    for name in ['collector.py', 'codes.json']:
        shutil.copyfile(source / name, destination / name)
        os.chmod(destination / name, 0o644)
    # Keep a rollback copy only for the files this deployment changes.
    rollback.mkdir(mode=0o700)
    shutil.copy2(args.proxy_config, rollback / 'Caddyfile')
    shutil.copy2('/opt/elo-admin/server.py', rollback / 'admin-server.py')
    shutil.copytree('/opt/elo-admin/static', rollback / 'admin-static')
    reader = Path('/srv/elo-admin/diagnostics-read-key')
    reader.write_text(key + '\n'); os.chmod(reader, 0o600); os.chown(reader, admin.pw_uid, admin.pw_gid)
    shutil.copyfile(args.admin_source / 'server.py', '/opt/elo-admin/server.py')
    os.chmod('/opt/elo-admin/server.py', 0o644)
    for file in (args.admin_source / 'static').iterdir():
        if file.is_file():
            target = Path('/opt/elo-admin/static') / file.name
            shutil.copyfile(file, target); os.chmod(target, 0o644)
    shutil.copyfile(source / 'elo-diagnostics.service', '/etc/systemd/system/elo-diagnostics.service')
    os.chmod('/etc/systemd/system/elo-diagnostics.service', 0o644)
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'enable', '--now', 'elo-diagnostics.service'])
    run(['systemctl', 'restart', 'elo-diagnostics.service'])
    previous = args.proxy_config.read_text()
    try:
        # Keep ownership and inode: the file may be bind-mounted by the proxy.
        args.proxy_config.write_text(proxy_config(previous))
        run(['docker', 'exec', args.proxy_container, 'caddy', 'validate', '--config', '/etc/caddy/Caddyfile', '--adapter', 'caddyfile'])
        run(['docker', 'restart', args.proxy_container])
        run(['systemctl', 'restart', 'elo-admin.service'])
    except Exception:
        args.proxy_config.write_text(previous)
        shutil.copy2(rollback / 'admin-server.py', '/opt/elo-admin/server.py')
        shutil.copytree(rollback / 'admin-static', '/opt/elo-admin/static', dirs_exist_ok=True)
        run(['docker', 'restart', args.proxy_container])
        run(['systemctl', 'restart', 'elo-admin.service'])
        raise
    print(json.dumps({'collector': 'active', 'reader': 'admin VPN and authentication', 'retention_days': 14}))


if __name__ == '__main__':
    main()
