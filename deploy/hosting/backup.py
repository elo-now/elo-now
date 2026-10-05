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
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from online_snapshot import capture, SourceChanged
from attachment_snapshot import AttachmentSnapshot
import urllib.parse
import xml.etree.ElementTree as ET

CONFIG = Path('/etc/elo-backup/config.json')
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


def clean_interrupted_staging(directory):
    # Call only while holding the job lock. Never follow a directory symlink or
    # traverse anything outside this dedicated, root-owned backup destination.
    for path in directory.iterdir():
        if path.is_symlink():
            continue
        if re.fullmatch(r'\.snapshot-[a-z0-9_]{8}', path.name) and path.is_dir():
            shutil.rmtree(path)
        elif path.name.endswith('.partial') and NAME.fullmatch(path.name[:-8]) and path.is_file():
            path.unlink()


def snapshot(config, directory):
    recipient = Path(config['recipient_file']).read_text().strip()
    if not re.fullmatch(r'age1[0-9a-z]+', recipient):
        raise ValueError('Expected an age X25519 public recipient')
    paths = config['paths']
    if not paths or any(not p.startswith('/') or not Path(p).exists() for p in paths):
        raise ValueError('A required backup path is missing')
    # Probe encryption before staging private data.
    run('age', '-r', recipient, input=b'', stdout=subprocess.DEVNULL)
    name = 'elo-ops-' + dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '.tar.gz.age'
    archive = directory / name
    partial = directory / (name + '.partial')
    if archive.exists() or partial.exists():
        raise FileExistsError('Backup destination already exists')
    try:
        # Plain staging is private and always removed, including on failure.
        # Retry a changing source without freezing production or accepting a
        # snapshot spanning a deletion/revocation and its previous state.
        for attempt in range(3):
            with tempfile.TemporaryDirectory(prefix='.snapshot-', dir=directory) as temporary:
                try:
                    attachments = AttachmentSnapshot(config['attachments']) if config.get('attachments') else None
                    manifest = attachments.capture(Path(temporary)) if attachments else None
                    capture(paths, Path(temporary))
                    if attachments:
                        attachments.verify_unchanged(manifest)
                except (SourceChanged, FileNotFoundError):
                    if attempt == 2:
                        raise
                    time.sleep(1)
                    continue
                with partial.open('xb') as output:
                    tar = subprocess.Popen(['tar', '-C', temporary, '-czf', '-', '--',
                                            *[p.lstrip('/') for p in paths],
                                            *(['elo-attachments'] if attachments else [])], stdout=subprocess.PIPE)
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
                break
    finally:
        partial.unlink(missing_ok=True)
    return archive


def load_config(path):
    # A delegated encrypted-export command must never choose root's input files
    # or redirect a privileged snapshot to an attacker-controlled recipient.
    if os.geteuid() == 0 and Path(path) != CONFIG:
        raise ValueError('Privileged backups require the fixed operator configuration')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as source:
        info = os.fstat(source.fileno())
        if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077
                or info.st_uid != os.geteuid()):
            raise ValueError('Backup configuration must be private and owned by the operator')
        data = source.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024:
        raise ValueError('Backup configuration is too large')
    return json.loads(data)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', default=str(CONFIG))
    parser.add_argument('--resume', action='store_true')
    parser.add_argument('--cleanup', action='store_true')
    export = parser.add_mutually_exclusive_group()
    export.add_argument('--list-encrypted', action='store_true')
    export.add_argument('--read-encrypted', metavar='NAME')
    args = parser.parse_args()
    os.umask(0o077)
    if args.resume:
        resume()
        return
    if args.list_encrypted or args.read_encrypted:
        config = load_config(args.config)
        directory = Path(config['destination'])
        if args.list_encrypted:
            print(json.dumps(sorted(p.name for p in directory.iterdir()
                                    if NAME.fullmatch(p.name) and p.is_file() and not p.is_symlink())))
        else:
            if not NAME.fullmatch(args.read_encrypted):
                raise ValueError('Invalid encrypted backup name')
            fd = os.open(directory / args.read_encrypted, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, 'rb') as source:
                if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                    raise ValueError('Expected a regular encrypted backup')
                shutil.copyfileobj(source, sys.stdout.buffer)
        return
    with open('/run/lock/elo-operational-backup.lock', 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        resume()
        config = load_config(args.config)
        days = config['retention_days']
        if not 1 <= days <= 7:
            raise ValueError('Operational retention must be between one and seven days')
        directory = Path(config['destination'])
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        clean_interrupted_staging(directory)
        if args.cleanup:
            return
        archive = snapshot(config, directory)
        cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)
        for path in directory.iterdir():
            if expired(path.name, cutoff):
                path.unlink()
                path.with_suffix(path.suffix + '.uploaded').unlink(missing_ok=True)
        # Services remain available during capture, encryption and transfer.
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
