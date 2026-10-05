#!/usr/bin/env python3
"""Decrypt a backup into a new, isolated directory; never activate services.

Only explicitly selected source roots, directories and regular files are accepted.
Keys and independently retained witness positions must be supplied separately.
This tool authenticates age ciphertext, not the remote sender or journal state.
"""
import argparse
import json
import os
from pathlib import Path
import stat
import subprocess
import tarfile
import tempfile
import threading

from pull_backup import (
    archive_path, BoundedTarInfo, MAX_ARCHIVE_BYTES, MAX_EXPANDED_BYTES, MAX_MEMBERS,
)


def restore(config, archive, destination):
    destination = Path(destination).absolute()
    parent = destination.parent
    info = parent.lstat()
    if (not stat.S_ISDIR(info.st_mode) or parent.resolve() != parent
            or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077):
        raise ValueError('Restore parent must be an owned private directory without symlinks')
    if destination.exists() or destination.is_symlink():
        raise FileExistsError('Restore destination must not exist')
    expected = config.get('required_paths')
    if (not isinstance(expected, list) or not expected
            or any(not isinstance(p, str) or not p.startswith('/') for p in expected)):
        raise ValueError('Restore requires explicit absolute source paths')
    expected = {archive_path(p.lstrip('/')) for p in expected}
    if any(a != b and a.startswith(b + '/') for a in expected for b in expected):
        raise ValueError('Overlapping restore roots are not allowed')
    archive = Path(archive)
    descriptor = os.open(archive, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as encrypted:
        info = os.fstat(encrypted.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_ARCHIVE_BYTES:
            raise ValueError('Expected a bounded regular encrypted archive')
        with tempfile.TemporaryDirectory(prefix='.restore-', dir=parent) as temporary:
            staging = Path(temporary) / 'tree'
            staging.mkdir(mode=0o700)
            process = subprocess.Popen(
                [config.get('age', 'age'), '-d', '-i', config['age_key']],
                stdin=encrypted, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            )
            timer = threading.Timer(300, process.kill)
            timer.start()
            try:
                seen, roots, size = set(), set(), 0
                with tarfile.open(fileobj=process.stdout, mode='r|gz',
                                  tarinfo=BoundedTarInfo) as source:
                    for member in source:
                        name = archive_path(member.name)
                        if name in seen or len(seen) >= MAX_MEMBERS:
                            raise ValueError('Duplicate or excessive archive members')
                        seen.add(name)
                        root = next((p for p in expected if name == p or name.startswith(p + '/')), None)
                        if root is None:
                            raise ValueError('Unexpected source root')
                        if name == root:
                            roots.add(root)
                        if not member.isdir() and not member.isfile():
                            raise ValueError('Restore rejects links and special files')
                        target = staging / name
                        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                        if member.isdir():
                            target.mkdir(mode=0o700, exist_ok=True)
                        else:
                            size += member.size
                            if size > MAX_EXPANDED_BYTES:
                                raise ValueError('Expanded backup exceeds size limit')
                            with source.extractfile(member) as content, target.open('xb') as output:
                                os.fchmod(output.fileno(), 0o600)
                                remaining = member.size
                                while remaining:
                                    chunk = content.read(min(remaining, 1024 * 1024))
                                    if not chunk:
                                        raise ValueError('Truncated archive member')
                                    output.write(chunk)
                                    remaining -= len(chunk)
                                output.flush()
                                os.fsync(output.fileno())
                # The tar end marker does not authenticate age's final chunk.
                # Consume the entire decryptor output and require successful exit.
                while process.stdout.read(1024 * 1024):
                    pass
                if process.wait() != 0:
                    raise ValueError('Backup decryption or authentication failed')
                if roots != expected:
                    raise ValueError('A required backup root is missing')
                for directory, _, _ in os.walk(staging):
                    os.chmod(directory, 0o700)
                if destination.exists() or destination.is_symlink():
                    raise FileExistsError('Restore destination appeared during verification')
                staging.rename(destination)
                directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
                return {'members': len(seen), 'bytes': size, 'services_started': False}
            finally:
                timer.cancel()
                process.stdout.close()
                if process.poll() is None:
                    process.kill()
                    process.wait()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--archive', required=True)
    parser.add_argument('--destination', required=True)
    args = parser.parse_args()
    os.umask(0o077)
    print(json.dumps(restore(json.loads(Path(args.config).read_text()), args.archive, args.destination)))
