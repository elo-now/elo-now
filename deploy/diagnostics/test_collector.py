import copy
from email.message import Message
import http.client
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
import collector

SOURCE = '192.0.2.1'


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
            self.assertEqual(self.store.ingest(report(f'{index:032x}'), SOURCE), 204)
        self.assertEqual(len(self.store.query('')['reports']), 3)
        self.assertEqual(self.store.ingest(report(f'{4:032x}'), SOURCE), 204)
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
            self.assertEqual(self.store.ingest(item, f'192.0.2.{index + 1}'), 204)
        first = self.store.query('')
        second = self.store.query('before=' + str(first['next']))
        ids = [r['sequence'] for r in first['reports'] + second['reports']]
        self.assertEqual(len(set(ids)), 65)
        self.assertIsNone(second['next'])

    def test_per_installation_and_global_caps_and_reset(self):
        self.assertTrue(self.store.allow_request(SOURCE))
        for i in range(20): self.assertEqual(self.store.ingest(report(f'{i:032x}'), SOURCE), 204)
        self.assertEqual(self.store.ingest(report('f'*32), SOURCE), 429)
        self.assertEqual(self.store.ingest(report('f'*32), '192.0.2.2'), 429)
        self.clock += 60
        self.assertTrue(self.store.allow_request(SOURCE))
        self.assertEqual(self.store.ingest(report('f'*32), SOURCE), 204)
        for index in range(599):
            self.assertTrue(self.store.allow_request(f'2001:db8:{index:x}::1'))
        self.assertFalse(self.store.allow_request('203.0.113.1'))
        self.assertLessEqual(len(self.store.network_requests), collector.MAX_REQUESTS)
        for index in range(1000):
            self.assertFalse(self.store.allow_request(f'2001:db8:ffff:{index:x}::1'))
        self.assertLessEqual(len(self.store.network_requests), collector.MAX_REQUESTS)

    def test_rotating_installations_and_ipv6_addresses_cannot_starve_another_network(self):
        accepted = 0
        for index in range(1000):
            source = f'2001:db8:1:2::{index + 1:x}'
            item = report(f'{index:032x}')
            item['installation'] = f'{index:032x}'
            if self.store.allow_request(source):
                accepted += self.store.ingest(item, source) == 204
        self.assertEqual(accepted, collector.REPORTS_PER_NETWORK)
        self.assertEqual(self.store.requests, collector.REQUESTS_PER_NETWORK)
        self.assertEqual(len(self.store.network_requests), 1)
        self.assertEqual(len(self.store.network_accepted), 1)
        other = report('f'*32)
        self.assertTrue(self.store.allow_request('2001:db8:1:3::1'))
        self.assertEqual(self.store.ingest(other, '2001:db8:1:3::1'), 204)
        for index in range(collector.REQUESTS_PER_NETWORK):
            address = SOURCE if index % 2 else '::ffff:192.0.2.1'
            self.assertTrue(self.store.allow_request(address))
        self.assertFalse(self.store.allow_request(SOURCE))
        self.assertFalse(self.store.allow_request('::ffff:192.0.2.1'))
        # Source addresses do not enter the saved report or any SQLite column.
        saved = self.store.db.execute('SELECT body FROM reports').fetchall()
        self.assertTrue(all('2001:db8' not in body and SOURCE not in body for (body,) in saved))
        self.clock += 60
        self.store.prune()
        self.assertFalse(self.store.network_requests)
        self.assertFalse(self.store.network_accepted)
        self.assertTrue(self.store.allow_request(SOURCE))

    def test_global_report_limit_stays_bounded_across_sources(self):
        for index in range(120):
            item = report(f'{index:032x}')
            item['installation'] = f'{index:032x}'
            self.assertEqual(self.store.ingest(item, f'192.0.2.{index + 1}'), 204)
        self.assertEqual(self.store.ingest(report('f'*32), '203.0.113.1'), 429)
        self.assertEqual(len(self.store.network_accepted), 120)

    def test_only_explicit_source_from_loopback_proxy_is_accepted(self):
        headers = Message()
        headers['X-Forwarded-For'] = SOURCE
        with self.assertRaises(ValueError): collector.proxy_source('127.0.0.1', headers)
        headers[collector.SOURCE_HEADER] = SOURCE
        self.assertEqual(collector.proxy_source('127.0.0.1', headers), SOURCE)
        with self.assertRaises(ValueError): collector.proxy_source('192.0.2.5', headers)
        headers[collector.SOURCE_HEADER] = '192.0.2.2'
        with self.assertRaises(ValueError): collector.proxy_source('127.0.0.1', headers)
        for value in ('example.org', '192.0.2.1, 192.0.2.2', 'fe80::1%en0'):
            headers = Message()
            headers[collector.SOURCE_HEADER] = value
            with self.assertRaises(ValueError): collector.proxy_source('127.0.0.1', headers)

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
            headers = {'Content-Type': 'application/json', collector.SOURCE_HEADER: SOURCE}
            self.assertEqual(request('POST', collector.INGEST, json.dumps(report()), {'Content-Type': 'application/json'})[0], 403)
            self.assertEqual(request('POST', collector.INGEST, json.dumps(report()), headers)[0], 204)
            status, body = request('GET', '/reports', headers={'Authorization':'Bearer ' + 'r'*40})
            self.assertEqual(status, 200); self.assertEqual(len(json.loads(body)['reports']), 1)
            self.assertEqual(request('POST', collector.INGEST, 'x'*16385, headers)[0], 413)
            self.assertEqual(request('POST', collector.INGEST, '{"password":"private"}', headers)[0], 400)
        finally:
            server.shutdown(); server.server_close(); thread.join()

    def test_failed_database_write_is_not_acknowledged(self):
        self.store.db.execute('PRAGMA query_only=ON')
        with self.assertRaises(collector.sqlite3.Error): self.store.ingest(report(), SOURCE)


if __name__ == '__main__':
    unittest.main()
