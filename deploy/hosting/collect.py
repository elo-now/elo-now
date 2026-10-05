#!/usr/bin/env python3
"""Export allowlisted operational aggregates; never export ciphertext or secrets."""
import argparse
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import urllib.request
import urllib.parse


def storage(database, mailbox):
    # Read the running WAL database consistently, without mutating its schema.
    uri = Path(database).resolve().as_uri() + '?mode=ro'
    with sqlite3.connect(uri, uri=True, timeout=2) as db:
        db.execute('PRAGMA query_only=ON')
        db.execute('BEGIN')
        columns = {row[1] for row in db.execute('PRAGMA table_info(objects)')}
        wire_size = 'COALESCE(o.wire_size_bytes,o.size_bytes)' if 'wire_size_bytes' in columns else 'o.size_bytes'
        count, size = db.execute(f'''WITH RECURSIVE scope(id) AS (
            SELECT ? UNION SELECT mailbox_id FROM mailbox_delegations JOIN scope ON parent_id=scope.id
        ), retained AS (SELECT DISTINCT o.object_id,{wire_size} AS size_bytes FROM deliveries d
            JOIN scope s ON s.id=d.mailbox_id JOIN objects o ON o.object_id=d.object_id)
        SELECT COUNT(*),COALESCE(SUM(size_bytes),0) FROM retained''', (mailbox,)).fetchone()
        quota = db.execute('SELECT quota_bytes FROM mailboxes WHERE mailbox_id=?', (mailbox,)).fetchone()
        return {'objects': count, 'bytes': size, 'quota_bytes': quota[0] if quota else None}


def membership(url):
    address = urllib.parse.urlsplit(url)
    if address.scheme != 'http' or address.hostname != '127.0.0.1' or address.path != '/stats':
        raise ValueError('Operator statistics must use a loopback endpoint')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(url, timeout=2) as response:
        value = json.loads(response.read(8192))
    return {key: value[key] for key in ['members', 'pending']
            if isinstance(value.get(key), int) and value[key] >= 0}


def request_sample(paths):
    durations, errors, transferred = [], 0, 0
    for path in paths:
        try:
            with open(path, 'rb') as log:
                log.seek(0, os.SEEK_END)
                length = log.tell()
                log.seek(max(0, length - 262144))
                lines = log.read().decode('ascii', errors='ignore').splitlines()[-1000:]
            for line in lines:
                parts = line.split()
                if len(parts) != 5:
                    continue
                timestamp, method, status, size, seconds = parts
                if method not in {'GET', 'POST', 'HEAD', 'OPTIONS'}:
                    continue
                if time.time() - datetime.fromisoformat(timestamp).timestamp() > 300:
                    continue
                duration = float(seconds) * 1000
                if not math.isfinite(duration) or duration < 0:
                    continue
                durations.append(duration)
                errors += int(status) >= 500
                transferred += int(size)
        except (OSError, ValueError):
            continue
    durations.sort()
    return {'requests': len(durations), 'server_errors': errors, 'response_bytes': transferred,
            'p95_ms': durations[min(len(durations)-1, int(len(durations)*.95))] if durations else None,
            'mean_ms': round(sum(durations)/len(durations), 1) if durations else None,
            'window_seconds': 300, 'max_requests_per_log': 1000}


def collect(config):
    spaces = []
    for entry in config['legacy_spaces']:
        row = {'name': entry['name'], 'membership': None, 'storage': None}
        try:
            # Only the mailbox ID is used. Never serialize the private config.
            private = json.loads(Path(entry['team_config']).read_text())
            row['storage'] = storage(entry['database'], private['spaces']['peer']['mailbox_id'])
        except (OSError, ValueError, KeyError, sqlite3.Error):
            pass
        try:
            row['membership'] = membership(entry['statistics_url'])
        except (OSError, ValueError, KeyError):
            pass
        spaces.append(row)
    disk = os.statvfs('/')
    return {'collected_at': datetime.now(timezone.utc).isoformat(), 'legacy_spaces': spaces,
            'requests': request_sample(config['access_logs']),
            'disk': {'total_bytes': disk.f_blocks*disk.f_frsize, 'available_bytes': disk.f_bavail*disk.f_frsize}}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True)
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text())
    output = Path(config['output'])
    value = collect(config)
    descriptor, temporary = tempfile.mkstemp(prefix='.metrics-', dir=output.parent)
    try:
        with os.fdopen(descriptor, 'w') as stream:
            json.dump(value, stream, allow_nan=False)
            stream.flush()
            os.fsync(stream.fileno())
        import pwd
        owner = pwd.getpwnam(config['owner'])
        os.chown(temporary, owner.pw_uid, owner.pw_gid)
        os.chmod(temporary, 0o600)
        os.replace(temporary, output)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


if __name__ == '__main__':
    main()
