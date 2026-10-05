#!/usr/bin/env python3
"""Pull encrypted snapshots to a separately controlled computer over SSH.

The VPS receives neither the backup decryption key nor access to this directory.
Remote absence/deletion never propagates locally. Age checks ciphertext integrity,
not sender identity. Remote input never authorizes deletion of independent copies.
"""
import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tempfile
import tarfile
import threading
import time

NAME = re.compile(r'elo-ops-(\d{8}T\d{6}Z)\.tar\.gz\.age\Z')
MAX_INVENTORY_BYTES = 256 * 1024
MAX_ARCHIVE_BYTES = 2 * 1024**3
MAX_DIRECTORY_BYTES = 8 * 1024**3
MIN_FREE_BYTES = 2 * 1024**3
MAX_EXPANDED_BYTES = 8 * 1024**3
MAX_MEMBERS = 100_000
MAX_METADATA_BYTES = 8 * 1024**2



def read_inventory(command):
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    timer = threading.Timer(30, process.kill)
    timer.start()
    try:
        data = process.stdout.read(MAX_INVENTORY_BYTES + 1)
        if len(data) > MAX_INVENTORY_BYTES:
            raise ValueError('Backup inventory exceeds local size limit')
        if process.wait() != 0:
            raise RuntimeError('Backup inventory transfer failed')
        return json.loads(data)
    finally:
        timer.cancel()
        process.stdout.close()
        if process.poll() is None:
            process.kill()
            process.wait()


def download_budget(directory):
    used = sum(p.stat().st_size for p in directory.rglob('*')
               if p.is_file() and not p.is_symlink())
    available = min(MAX_ARCHIVE_BYTES, MAX_DIRECTORY_BYTES - used,
                    shutil.disk_usage(directory).free - MIN_FREE_BYTES)
    if available <= 0:
        raise RuntimeError('Insufficient local backup space; existing copies preserved')
    return available


def timestamp(name):
    match = NAME.fullmatch(name)
    if not match:
        raise ValueError('Invalid backup name')
    return dt.datetime.strptime(match[1], '%Y%m%dT%H%M%SZ').replace(tzinfo=dt.timezone.utc)


def candidates(names, now):
    return sorted({name for name in names if isinstance(name, str) and NAME.fullmatch(name)
                   and now - dt.timedelta(days=7) <= timestamp(name) <= now + dt.timedelta(minutes=5)})


class BoundedTarInfo(tarfile.TarInfo):
    @classmethod
    def frombuf(cls, buf, encoding, errors):
        member = super().frombuf(buf, encoding, errors)
        if member.size < 0 or member.size > MAX_EXPANDED_BYTES or (not member.isfile() and member.size > MAX_METADATA_BYTES):
            raise ValueError('Archive member exceeds its size limit')
        return member


def archive_path(name):
    path = PurePosixPath(name)
    if (path.is_absolute() or '..' in path.parts or not path.parts
            or len(name.encode('utf-8')) > 4096):
        raise ValueError('Unsafe backup archive path')
    return str(path)


def verify_archive(config, archive):
    """Check a bounded archive without extracting files or trusting its sender."""
    expected = config.get('required_paths')
    if (not isinstance(expected, list) or not expected
            or any(not isinstance(p, str) or not p.startswith('/') for p in expected)):
        raise ValueError('Independent backup checks require explicit source paths')
    expected = {archive_path(p.lstrip('/')) for p in expected}
    require_attachments = config.get('require_attachments', True)
    if type(require_attachments) is not bool:
        raise ValueError('Invalid attachment backup requirement')
    process = subprocess.Popen([config['age'], '-d', '-i', config['age_key'], str(archive)],
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    deadline = time.monotonic() + 120
    timer = threading.Timer(120, process.kill)
    timer.start()
    try:
        members, source_roots, objects, manifest = set(), set(), {}, None
        total, name_bytes = 0, 0
        with tarfile.open(fileobj=process.stdout, mode='r|gz', tarinfo=BoundedTarInfo) as tar:
            for member in tar:
                if time.monotonic() > deadline:
                    raise TimeoutError('Backup validation exceeded its time budget')
                name = archive_path(member.name)
                name_bytes += len(name.encode('utf-8'))
                if name in members or len(members) >= MAX_MEMBERS or name_bytes > MAX_METADATA_BYTES:
                    raise ValueError('Duplicate or excessive backup entries')
                members.add(name)
                if not (member.isfile() or member.isdir() or member.issym()):
                    raise ValueError('Unsupported backup archive member')
                if member.isfile() or member.isdir():
                    source_roots.add(name)
                if not member.isfile():
                    continue
                total += member.size
                if total > MAX_EXPANDED_BYTES:
                    raise ValueError('Expanded backup exceeds its byte budget')
                source = tar.extractfile(member)
                digest, size, metadata = hashlib.sha256(), 0, bytearray()
                is_manifest = name == 'elo-attachments/manifest.json'
                if is_manifest and member.size > MAX_METADATA_BYTES:
                    raise ValueError('Attachment manifest is too large')
                for chunk in iter(lambda: source.read(65536), b''):
                    if time.monotonic() > deadline:
                        raise TimeoutError('Backup validation exceeded its time budget')
                    size += len(chunk)
                    digest.update(chunk)
                    if is_manifest:
                        metadata.extend(chunk)
                if size != member.size:
                    raise ValueError('Truncated backup member')
                if name.startswith('elo-attachments/spaces/'):
                    objects[name] = (size, digest.hexdigest())
                if is_manifest:
                    manifest = json.loads(metadata)
        # Drain the encrypted stream: age must validate its final authentication
        # tag even when the tar reader has already reached the end marker.
        for _ in iter(lambda: process.stdout.read(65536), b''):
            pass
        if process.wait() != 0:
            raise RuntimeError('Backup decryption failed integrity validation')
        if not expected.issubset(source_roots) or not total:
            raise ValueError('Backup omits an expected source')
        if require_attachments and manifest is None:
            raise ValueError('Backup omits required attachment inventory')
        if manifest is not None:
            if manifest.get('version') != 1 or not isinstance(manifest.get('spaces'), dict):
                raise ValueError('Invalid attachment backup manifest')
            recorded = {}
            for space, state in manifest['spaces'].items():
                if (not re.fullmatch('[0-9a-f]{64}', space) or not isinstance(state, dict)
                        or not re.fullmatch('[0-9a-f]{64}', state.get('revision', ''))
                        or not isinstance(state.get('objects'), list)):
                    raise ValueError('Invalid attachment backup Space')
                for obj in state['objects']:
                    name = obj.get('object')
                    if not isinstance(name, str) or not re.fullmatch('[0-9a-f]{32}', name):
                        raise ValueError('Invalid attachment backup object')
                    name = f'elo-attachments/spaces/{space}/{name}'
                    if name in recorded:
                        raise ValueError('Duplicate attachment backup object')
                    size, checksum = obj.get('size'), obj.get('sha256')
                    if (type(size) is not int or not 0 < size <= 6 * 1024**2
                            or not isinstance(checksum, str) or not re.fullmatch('[0-9a-f]{64}', checksum)):
                        raise ValueError('Invalid attachment backup metadata')
                    recorded[name] = (size, checksum)
            if objects != recorded:
                raise ValueError('Attachment backup bytes do not match the inventory')
    finally:
        timer.cancel()
        process.stdout.close()
        if process.poll() is None:
            process.kill()
            process.wait()


def pull(config):
    directory = Path(config['destination'])
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    ssh = [config.get('ssh', '/usr/bin/ssh'), '-i', config['ssh_key'],
           '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'ForwardAgent=no',
           '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=10',
           config['host'], 'sudo -n /usr/bin/python3 /opt/elo/hosting/backup.py']
    names = read_inventory([*ssh, '--list-encrypted'])
    if not isinstance(names, list) or len(names) > 1000:
        raise ValueError('Invalid backup inventory')
    now = dt.datetime.now(dt.timezone.utc)
    names = candidates(names, now)
    if not names or now - timestamp(names[-1]) > dt.timedelta(hours=36):
        raise RuntimeError('No recent encrypted snapshot is available')
    # One newest snapshot per run bounds work even with a hostile inventory.
    # Older local copies remain independent of remote retention or deletion.
    names = names[-1:]
    for name in names:
        target = directory / name
        if target.exists():
            continue
        budget = download_budget(directory)
        with tempfile.TemporaryDirectory(prefix='.pull-', dir=directory) as temporary:
            partial = Path(temporary) / 'snapshot.age'
            with partial.open('xb') as output:
                # Bound disk consumption even if the remote host is compromised.
                process = subprocess.Popen([*ssh, '--read-encrypted', name],
                                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
                timer = threading.Timer(300, process.kill)
                timer.start()
                try:
                    total = 0
                    for chunk in iter(lambda: process.stdout.read(1024 * 1024), b''):
                        total += len(chunk)
                        if total > budget:
                            raise ValueError('Encrypted snapshot exceeds local size limit')
                        output.write(chunk)
                    if process.wait() != 0:
                        raise RuntimeError('Encrypted snapshot transfer failed')
                    output.flush()
                    os.fsync(output.fileno())
                finally:
                    timer.cancel()
                    process.stdout.close()
                    if process.poll() is None:
                        process.kill()
                        process.wait()
            verify_archive(config, partial)
            partial.rename(target)
    verify_archive(config, directory / names[-1])
    # Even a structurally valid archive can be forged by a compromised VPS,
    # which holds the public age recipient. Only an operator may retire old
    # independent copies after a separate restore check; remote data cannot.
    print('Independent encrypted backup passed integrity and structure checks: ' + names[-1])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True)
    args = parser.parse_args()
    os.umask(0o077)
    config = json.loads(Path(args.config).read_text())
    with open(args.config + '.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        pull(config)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # No remote stderr, private configuration or credential paths in logs.
        print(f'Independent backup pull failed ({type(error).__name__}).')
        raise SystemExit(1)
