#!/usr/bin/env python3
"""Consistent, age-encrypted operational backups; no private key on the server."""
import argparse
import datetime as dt
import fcntl
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import urllib.parse
import xml.etree.ElementTree as ET

STATE = Path('/run/elo-backup-resume.json')
NAME = re.compile(r'elo-ops-(\d{8}T\d{6}Z)\.tar\.gz\.age\Z')


def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def resume():
    if STATE.exists():
        services = json.loads(STATE.read_text())
        if services:
            run('systemctl', 'start', *services)
        STATE.unlink()


def webdav(base, method, name='', upload=None):
    # Keep the private collection URL out of argv, logs and error messages.
    url = base.rstrip('/') + '/' + name
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != 'http' or parsed.hostname not in ('127.0.0.1', '::1'):
        raise ValueError('Backup WebDAV must be an isolated loopback endpoint')
    options = ['silent', 'show-error', 'noproxy = "*"', 'connect-timeout = 5',
               'max-time = 300', f'request = "{method}"',
               'url = ' + json.dumps(url), 'write-out = "\\n%{http_code}"']
    if method == 'PROPFIND':
        options += ['header = "Depth: 1"']
    if upload:
        options += ['upload-file = ' + json.dumps(str(upload))]
    result = run('curl', '--config', '-', input='\n'.join(options),
                 capture_output=True, text=True)
    body, status = result.stdout.rsplit('\n', 1)
    code = int(status)
    if not (200 <= code < 300 or method == 'MKCOL' and code == 405
            or method == 'DELETE' and code == 404):
        raise RuntimeError(f'Backup storage returned HTTP {code}')
    return body


def expired(name, cutoff):
    match = NAME.fullmatch(name)
    return bool(match and dt.datetime.strptime(match[1], '%Y%m%dT%H%M%SZ')
                .replace(tzinfo=dt.timezone.utc) < cutoff)


def snapshot(config, directory):
    recipient = Path(config['recipient_file']).read_text().strip()
    if not re.fullmatch(r'age1[0-9a-z]+', recipient):
        raise ValueError('Expected an age X25519 public recipient')
    paths = config['paths']
    if not paths or any(not p.startswith('/') or not Path(p).exists() for p in paths):
        raise ValueError('A required backup path is missing')
    # Probe encryption before interrupting any service.
    run('age', '-r', recipient, input=b'', stdout=subprocess.DEVNULL)
    active = [s for s in config['services'] if subprocess.run(
        ['systemctl', 'is-active', '--quiet', s]).returncode == 0]
    name = 'elo-ops-' + dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '.tar.gz.age'
    archive = directory / name
    partial = directory / (name + '.partial')
    if archive.exists() or partial.exists():
        raise FileExistsError('Backup destination already exists')
    STATE.write_text(json.dumps(active))
    try:
        if active:
            run('systemctl', 'stop', *active)
        with partial.open('xb') as output:
            tar = subprocess.Popen(['tar', '-C', '/', '-czf', '-', '--',
                                    *[p.lstrip('/') for p in paths]], stdout=subprocess.PIPE)
            try:
                encrypted = subprocess.run(['age', '-r', recipient], stdin=tar.stdout,
                                           stdout=output)
                tar.stdout.close()
                status = tar.wait()
                if encrypted.returncode or status:
                    raise RuntimeError('Snapshot or encryption failed')
                output.flush()
                os.fsync(output.fileno())
            finally:
                if tar.poll() is None:
                    tar.kill()
                    tar.wait()
        partial.rename(archive)
    finally:
        resume()
        partial.unlink(missing_ok=True)
    return archive


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', default='/etc/elo-backup/config.json')
    parser.add_argument('--resume', action='store_true')
    args = parser.parse_args()
    os.umask(0o077)
    if args.resume:
        resume()
        return
    with open('/run/lock/elo-operational-backup.lock', 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        resume()
        config = json.loads(Path(args.config).read_text())
        days = config['retention_days']
        if not 1 <= days <= 7:
            raise ValueError('Operational retention must be between one and seven days')
        directory = Path(config['destination'])
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)
        for path in directory.iterdir():
            if expired(path.name, cutoff):
                path.unlink()
                path.with_suffix(path.suffix + '.uploaded').unlink(missing_ok=True)
        archive = snapshot(config, directory)
        # Services are already available again while off-site transfer runs.
        base = config['offsite_url']
        webdav(base, 'MKCOL')
        cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)
        for path in sorted(directory.iterdir()):
            if NAME.fullmatch(path.name) and not expired(path.name, cutoff):
                marker = path.with_suffix(path.suffix + '.uploaded')
                if not marker.exists():
                    webdav(base, 'PUT', path.name, path)
                    marker.touch(mode=0o600)
        listing = ET.fromstring(webdav(base, 'PROPFIND'))
        for href in listing.iter('{DAV:}href'):
            name = urllib.parse.unquote(urllib.parse.urlsplit(href.text or '').path).rstrip('/').rsplit('/', 1)[-1]
            if expired(name, cutoff):
                webdav(base, 'DELETE', name)
        print(f'Encrypted backup stored locally and off-site: {archive.name}')


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    try:
        main()
    except Exception as error:
        # Exceptions from subprocesses must not expose private URLs/configuration.
        print(f'Operational backup failed ({type(error).__name__}); inspect service status.', file=sys.stderr)
        sys.exit(1)
