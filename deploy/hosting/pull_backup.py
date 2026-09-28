#!/usr/bin/env python3
"""Pull encrypted snapshots to a separately controlled computer over SSH.

The VPS receives neither the backup decryption key nor access to this directory.
Remote absence/deletion never propagates locally. Retention is applied only after
a fresh snapshot is authenticated with age, and always preserves two copies.
"""
import argparse
import datetime as dt
import fcntl
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

NAME = re.compile(r'elo-ops-(\d{8}T\d{6}Z)\.tar\.gz\.age\Z')


def timestamp(name):
    match = NAME.fullmatch(name)
    if not match:
        raise ValueError('Invalid backup name')
    return dt.datetime.strptime(match[1], '%Y%m%dT%H%M%SZ').replace(tzinfo=dt.timezone.utc)


def candidates(names, now):
    return sorted({name for name in names if isinstance(name, str) and NAME.fullmatch(name)
                   and now - dt.timedelta(days=7) <= timestamp(name) <= now + dt.timedelta(minutes=5)})


def prune(directory, now):
    files = sorted(p for p in directory.iterdir() if NAME.fullmatch(p.name)
                   and p.is_file() and not p.is_symlink())
    for path in files[:-2]:
        if timestamp(path.name) < now - dt.timedelta(days=7):
            path.unlink()


def pull(config):
    directory = Path(config['destination'])
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    ssh = [config.get('ssh', '/usr/bin/ssh'), '-i', config['ssh_key'],
           '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'ForwardAgent=no',
           '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=10',
           config['host'], 'sudo -n /usr/bin/python3 /opt/elo/hosting/backup.py']
    listed = subprocess.run([*ssh, '--list-encrypted'], check=True, capture_output=True,
                            text=True, timeout=30)
    names = json.loads(listed.stdout)
    if not isinstance(names, list) or len(names) > 1000:
        raise ValueError('Invalid backup inventory')
    now = dt.datetime.now(dt.timezone.utc)
    names = candidates(names, now)
    if not names or now - timestamp(names[-1]) > dt.timedelta(hours=36):
        raise RuntimeError('No recent encrypted snapshot is available')
    for name in names:
        target = directory / name
        if target.exists():
            continue
        with tempfile.TemporaryDirectory(prefix='.pull-', dir=directory) as temporary:
            partial = Path(temporary) / 'snapshot.age'
            with partial.open('xb') as output:
                # Bound disk consumption even if the remote host is compromised.
                process = subprocess.Popen([*ssh, '--read-encrypted', name],
                                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
                import threading
                timer = threading.Timer(300, process.kill)
                timer.start()
                try:
                    total = 0
                    for chunk in iter(lambda: process.stdout.read(1024 * 1024), b''):
                        total += len(chunk)
                        if total > 2 * 1024**3:
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
            subprocess.run([config['age'], '-d', '-i', config['age_key'], str(partial)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           check=True, timeout=120)
            partial.rename(target)
    # Authenticate even an existing newest copy before allowing local retention.
    subprocess.run([config['age'], '-d', '-i', config['age_key'], str(directory / names[-1])],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=120)
    prune(directory, now)
    print('Independent encrypted backup verified: ' + names[-1])


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
