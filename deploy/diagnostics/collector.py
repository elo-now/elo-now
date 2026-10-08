#!/usr/bin/env python3
"""Opt-in beta errors: anonymous bounded ingestion, authenticated local reads."""
import argparse
import collections
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import sqlite3
import threading
import time
from urllib.parse import parse_qs, urlsplit

VOCABULARY = {k: set(v) for k, v in json.loads(Path(__file__).with_name('codes.json').read_text()).items()}
INGEST = '/diagnostics/v1/errors'
RETENTION = 14 * 86400
MAX_ROWS = 10000


def exact(value, fields):
    return isinstance(value, dict) and set(value) == set(fields.split())


def matches(pattern, value):
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def event(v):
    return (exact(v, 'kind source code elapsed_ms') and v['kind'] in ('event', 'error')
            and isinstance(v['source'], str) and isinstance(v['code'], str)
            and v['code'] in VOCABULARY.get(v['source'], ())
            and (v['elapsed_ms'] is None or type(v['elapsed_ms']) is int and 0 <= v['elapsed_ms'] <= 600000))


def valid(v, now):
    if not (exact(v, 'schema installation platform architecture version build report')
            and type(v['schema']) is int and v['schema'] == 1
            and matches(r'[a-f0-9]{32}', v['installation'])
            and v['platform'] in ('ios', 'android', 'macos')
            and v['architecture'] in ('aarch64', 'x86_64', 'arm', 'x86')
            and matches(r'[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}', v['version'])
            and matches(r'([0-9]{1,16}|unknown)', v['build'])):
        return False
    r = v['report']
    return (exact(r, 'id created_at event breadcrumbs') and matches(r'[a-f0-9]{32}', r['id'])
            and type(r['created_at']) is int and now - 7 * 86400 <= r['created_at'] <= now + 300
            and event(r['event']) and r['event']['kind'] == 'error'
            and isinstance(r['breadcrumbs'], list) and len(r['breadcrumbs']) <= 12
            and all(event(e) for e in r['breadcrumbs']))


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('Duplicate field')
        value[key] = item
    return value


def decode(data):
    return json.loads(data, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Invalid JSON')))


class Store:
    def __init__(self, path, clock=time.time, max_rows=MAX_ROWS):
        self.path, self.clock, self.max_rows = path, clock, max_rows
        self.lock = threading.RLock()
        self.minute, self.requests, self.accepted = -1, 0, collections.Counter()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute('PRAGMA auto_vacuum=FULL')
        self.db.execute('PRAGMA secure_delete=ON')
        self.db.execute('PRAGMA max_page_count=32768')  # At most 128 MiB at the default 4 KiB page size.
        self.db.execute('CREATE TABLE IF NOT EXISTS reports (seq INTEGER PRIMARY KEY AUTOINCREMENT, '
                        'received INTEGER NOT NULL, installation TEXT NOT NULL, id TEXT NOT NULL, '
                        'platform TEXT, version TEXT, build TEXT, code TEXT, body TEXT, UNIQUE(installation,id))')
        self.db.execute('CREATE INDEX IF NOT EXISTS reports_received ON reports(received)')
        self.db.commit()
        self.prune()

    def prune(self):
        with self.lock, self.db:
            self.db.execute('DELETE FROM reports WHERE received <= ?', (int(self.clock()) - RETENTION,))
            self.db.execute('DELETE FROM reports WHERE seq IN (SELECT seq FROM reports ORDER BY seq DESC LIMIT -1 OFFSET ?)', (self.max_rows,))

    def allow_request(self):
        with self.lock:
            minute = int(self.clock()) // 60
            if minute != self.minute:
                self.minute, self.requests, self.accepted = minute, 0, collections.Counter()
            self.requests += 1
            return self.requests <= 600

    def ingest(self, value):
        now = int(self.clock())
        if not valid(value, now):
            return 400
        r = value['report']
        with self.lock, self.db:
            if self.db.execute('SELECT 1 FROM reports WHERE installation=? AND id=?', (value['installation'], r['id'])).fetchone():
                return 204
            if self.accepted.total() >= 120 or self.accepted[value['installation']] >= 20:
                return 429
            self.accepted[value['installation']] += 1
            self.db.execute('INSERT INTO reports(received,installation,id,platform,version,build,code,body) VALUES(?,?,?,?,?,?,?,?)',
                            (now, value['installation'], r['id'], value['platform'], value['version'], value['build'], r['event']['code'], json.dumps(value, separators=(',', ':'))))
            self.prune()
        return 204

    def query(self, query):
        args = parse_qs(query, keep_blank_values=True, strict_parsing=True, max_num_fields=8)
        patterns = {'platform': r'ios|android|macos', 'version': r'[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}',
                    'build': r'[0-9]{1,16}|unknown', 'code': r'[a-zA-Z0-9_.:-]{1,160}', 'installation': r'[a-f0-9]{32}',
                    'before': r'[0-9]{1,18}'}
        clauses, params = ['received > ?'], [int(self.clock()) - RETENTION]
        for key, values in args.items():
            if key not in patterns or len(values) != 1 or not matches(patterns[key], values[0]):
                raise ValueError('Invalid filter')
            clauses.append('seq < ?' if key == 'before' else key + ' = ?')
            params.append(int(values[0]) if key == 'before' else values[0])
        with self.lock:
            rows = self.db.execute('SELECT seq,received,body FROM reports WHERE ' + ' AND '.join(clauses) + ' ORDER BY seq DESC LIMIT 51', params).fetchall()
        return {'reports': [dict(json.loads(body), sequence=seq, received_at=received) for seq, received, body in rows[:50]],
                'next': rows[49][0] if len(rows) > 50 else None, 'retention_days': 14}


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.0'

    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def log_message(self, *_):
        pass  # Never persist IPs, request headers, URLs or raw bodies.

    def reply(self, status, value=None):
        body = b'' if value is None else json.dumps(value).encode()
        self.send_response(status)
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Type', 'application/json')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Length', str(len(body)))
        if status == 429:
            self.send_header('Retry-After', '60')
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path != INGEST:
            return self.reply(404)
        if not self.server.store.allow_request():
            return self.reply(429)
        if (self.headers.get_all('Transfer-Encoding') or len(self.headers.get_all('Content-Type', [])) != 1
                or self.headers.get('Content-Type') not in ('application/json', 'application/json; charset=utf-8')):
            return self.reply(415)
        lengths = self.headers.get_all('Content-Length', [])
        if len(lengths) != 1 or not matches(r'[0-9]{1,6}', lengths[0]) or not 0 < int(lengths[0]) <= 16384:
            return self.reply(413)
        try:
            data = self.rfile.read(int(lengths[0]))
            if len(data) != int(lengths[0]):
                return self.reply(400)
            self.reply(self.server.store.ingest(decode(data)))
        except (ValueError, TypeError, UnicodeError, RecursionError):
            self.reply(400)
        except TimeoutError:
            self.reply(408)
        except sqlite3.Error:
            self.reply(503)

    def do_GET(self):
        parts = urlsplit(self.path)
        if parts.path != '/reports' or len(self.path) > 2048:
            return self.reply(404)
        auth = self.headers.get_all('Authorization', [])
        if len(auth) != 1 or not auth[0].isascii() or not hmac.compare_digest(auth[0], 'Bearer ' + self.server.read_key):
            return self.reply(403)
        try:
            self.reply(200, self.server.store.query(parts.query))
        except ValueError:
            self.reply(400)
        except sqlite3.Error:
            self.reply(503)


class Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 16
    allow_reuse_address = True

    def __init__(self, address, store, read_key):
        if address[0] != '127.0.0.1' or not matches(r'[a-zA-Z0-9_-]{32,128}', read_key):
            raise ValueError('Loopback and a read credential are required')
        self.store, self.read_key = store, read_key
        self.slots = threading.BoundedSemaphore(8)
        super().__init__(address, Handler)

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            return self.shutdown_request(request)
        try:
            super().process_request(request, address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()

    def handle_error(self, *_):
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path('/srv/elo-diagnostics'))
    parser.add_argument('--port', type=int, default=17930)
    args = parser.parse_args()
    if os.getuid() == 0:
        parser.error('Run as an unprivileged user')
    os.umask(0o077)
    store = Store(args.root / 'reports.sqlite')
    server = Server(('127.0.0.1', args.port), store, (args.root / 'read-key').read_text().strip())
    def cleanup():
        while True:
            time.sleep(60)
            try:
                store.prune()
            except sqlite3.Error:
                pass
    threading.Thread(target=cleanup, daemon=True).start()
    server.serve_forever(poll_interval=0.25)


if __name__ == '__main__':
    main()
