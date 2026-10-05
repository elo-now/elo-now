"""The operator snapshot must contain aggregates, never private configuration."""
import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('hosting_collect', Path(__file__).with_name('collect.py'))
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


class AggregateTest(unittest.TestCase):
    def test_descendant_storage_is_scoped_and_secrets_are_not_exported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dbpath = root / 'replica.sqlite'
            with sqlite3.connect(dbpath) as db:
                db.executescript('''CREATE TABLE mailboxes(mailbox_id TEXT,quota_bytes INTEGER);
                    CREATE TABLE mailbox_delegations(mailbox_id TEXT,parent_id TEXT);
                    CREATE TABLE objects(object_id TEXT,size_bytes INTEGER,ciphertext BLOB);
                    CREATE TABLE deliveries(mailbox_id TEXT,object_id TEXT);
                    INSERT INTO mailboxes VALUES ('a',1000),('child',100),('other',1000);
                    INSERT INTO mailbox_delegations VALUES ('child','a');
                    INSERT INTO objects VALUES ('one',5,'private ciphertext'),('two',7,'private file'),('foreign',500,'foreign ciphertext');
                    INSERT INTO deliveries VALUES ('a','one'),('child','one'),('child','two'),('other','foreign');''')
            private = root / 'private.json'
            private.write_text(json.dumps({'password': 'NEVER_EXPORT_PASSWORD', 'spaces': {'peer': {
                'mailbox_id': 'a', 'read_token': 'NEVER_EXPORT_CAPABILITY'}}}))
            config = {'legacy_spaces': [{'name': 'Demo', 'team_config': str(private), 'database': str(dbpath),
                                        'statistics_url': 'http://127.0.0.1:8791/stats'}], 'access_logs': []}
            with patch.object(collector, 'membership', return_value={'members': 3, 'pending': 1}):
                result = collector.collect(config)
            self.assertEqual(result['legacy_spaces'][0]['storage'], {'objects': 2, 'bytes': 12, 'quota_bytes': 1000})
            with sqlite3.connect(dbpath) as db:
                db.executescript('''ALTER TABLE objects ADD COLUMN wire_size_bytes INTEGER;
                    UPDATE objects SET wire_size_bytes=50 WHERE object_id='one';''')
            self.assertEqual(collector.storage(dbpath, 'a'), {'objects': 2, 'bytes': 57, 'quota_bytes': 1000})
            rendered = json.dumps(result)
            for forbidden in ['NEVER_EXPORT', 'ciphertext BLOB', 'private file', 'foreign', 'read_token', 'password']:
                self.assertNotIn(forbidden, rendered)

    def test_unavailable_source_is_explicit_and_operator_urls_cannot_leave_loopback(self):
        result = collector.collect({'legacy_spaces': [{'name': 'Demo', 'team_config': '/missing-config',
            'database': '/missing-db', 'statistics_url': 'https://example.org/stats'}], 'access_logs': []})
        self.assertIsNone(result['legacy_spaces'][0]['membership'])
        self.assertIsNone(result['legacy_spaces'][0]['storage'])
        self.assertIsNone(result['requests']['p95_ms'])


if __name__ == '__main__':
    unittest.main()
