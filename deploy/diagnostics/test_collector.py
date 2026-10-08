import copy
import http.client
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
import collector


def report(identifier='a' * 32):
    return {'schema': 1, 'installation': 'b' * 32, 'platform': 'ios', 'architecture': 'aarch64',
            'version': '1.0.6', 'build': '1179', 'report': {'id': identifier, 'created_at': 1800000000,
            'event': {'kind': 'error', 'source': 'test', 'code': 'diagnostics_test', 'elapsed_ms': None}, 'breadcrumbs': []}}


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.clock = 1800000000
        self.path = Path(self.temp.name) / 'reports.sqlite'
        self.store = collector.Store(self.path, clock=lambda: self.clock, max_rows=3)

    def tearDown(self):
        self.store.db.close()
        self.temp.cleanup()

    def test_strict_schema_rejects_raw_and_malformed_data(self):
        self.assertTrue(collector.valid(report(), self.clock))
        for path, value in [(['message'], 'private'), (['schema'], True), (['report', 'event', 'code'], 'private'),
                            (['report', 'event', 'source'], ['test']), (['report', 'event', 'elapsed_ms'], True),
                            (['report', 'breadcrumbs'], [None]), (['report', 'created_at'], self.clock - 8*86400),
                            (['report', 'created_at'], self.clock + 301), (['platform'], 'linux')]:
            item = report()
            target = item
            for key in path[:-1]: target = target[key]
            target[path[-1]] = value
            with self.subTest(path=path): self.assertFalse(collector.valid(item, self.clock))
        with self.assertRaises(ValueError): collector.decode('{"a":1,"a":2}')
        with self.assertRaises(ValueError): collector.decode('{"a":NaN}')

    def test_durable_deduplication_filters_and_retention(self):
        for index in range(5):
            self.assertEqual(self.store.ingest(report(f'{index:032x}')), 204)
        self.assertEqual(len(self.store.query('')['reports']), 3)
        self.assertEqual(self.store.ingest(report(f'{4:032x}')), 204)
        self.store.db.close()
        self.store = collector.Store(self.path, clock=lambda: self.clock, max_rows=3)
        self.assertEqual(len(self.store.query('platform=ios&build=1179')['reports']), 3)
        self.assertEqual(len(self.store.query('platform=android')['reports']), 0)
        for query in ['code=x%27+OR+1%3D1', 'platform=ios&platform=macos', 'token=secret', 'before=-1']:
            with self.assertRaises(ValueError): self.store.query(query)
        self.clock += collector.RETENTION + 1
        self.assertEqual(self.store.query('')['reports'], [])
        self.store.prune()
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM reports').fetchone()[0], 0)

    def test_pagination_has_no_duplicates(self):
        self.store.max_rows = 200
        for index in range(65):
            item = report(f'{index:032x}'); item['installation'] = f'{index:032x}'
            self.assertEqual(self.store.ingest(item), 204)
        first = self.store.query('')
        second = self.store.query('before=' + str(first['next']))
        ids = [r['sequence'] for r in first['reports'] + second['reports']]
        self.assertEqual(len(set(ids)), 65)
        self.assertIsNone(second['next'])

    def test_per_installation_and_global_caps_and_reset(self):
        self.assertTrue(self.store.allow_request())
        for i in range(20): self.assertEqual(self.store.ingest(report(f'{i:032x}')), 204)
        self.assertEqual(self.store.ingest(report('f'*32)), 429)
        self.clock += 60
        self.store.allow_request()
        self.assertEqual(self.store.ingest(report('f'*32)), 204)
        for _ in range(599): self.store.allow_request()
        self.assertFalse(self.store.allow_request())

    def test_http_write_only_and_private_read_boundary(self):
        server = collector.Server(('127.0.0.1', 0), self.store, 'r'*40)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        def request(method, path, body=None, headers=None):
            client = http.client.HTTPConnection(*server.server_address, timeout=3)
            client.request(method, path, body=body, headers=headers or {})
            response = client.getresponse(); result = (response.status, response.read()); client.close(); return result
        try:
            self.assertEqual(request('GET', collector.INGEST)[0], 404)
            self.assertEqual(request('GET', '/reports')[0], 403)
            self.assertEqual(request('POST', '/reports', '{}', {'Content-Type': 'application/json'})[0], 404)
            self.assertEqual(request('POST', collector.INGEST, json.dumps(report()), {'Content-Type': 'application/json'})[0], 204)
            status, body = request('GET', '/reports', headers={'Authorization':'Bearer ' + 'r'*40})
            self.assertEqual(status, 200); self.assertEqual(len(json.loads(body)['reports']), 1)
            self.assertEqual(request('POST', collector.INGEST, 'x'*16385, {'Content-Type':'application/json'})[0], 413)
            self.assertEqual(request('POST', collector.INGEST, '{"password":"private"}', {'Content-Type':'application/json'})[0], 400)
        finally:
            server.shutdown(); server.server_close(); thread.join()

    def test_failed_database_write_is_not_acknowledged(self):
        self.store.db.execute('PRAGMA query_only=ON')
        with self.assertRaises(collector.sqlite3.Error): self.store.ingest(report())


if __name__ == '__main__':
    unittest.main()
