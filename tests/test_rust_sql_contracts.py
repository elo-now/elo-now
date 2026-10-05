"""Execute the exact SQL embedded in T01 Rust via include_str!.

These are Python/SQLite contract checks, NOT execution or compilation of Rust.
They supplement (not replace) the tests in crates/elo-core and crates/elo-cli.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SQL_DIR = ROOT / "crates/elo-core/src/store/sql"
SQL = {path.stem: path.read_text() for path in SQL_DIR.glob("*.sql")}
# Current production queries also depend on inbox and replica-copy metadata.
MIGRATION = "\n".join(
    path.read_text() for path in sorted((ROOT / "migrations").glob("[0-9][0-9][0-9]_client*.sql"))
)


def digest(domain: bytes, data: bytes) -> str:
    return hashlib.sha256(domain + data).hexdigest()


def sample(seed: int = 1, target_count: int = 2) -> dict:
    ciphertext = bytes([seed]) * 80  # PUBLIC OPAQUE FIXTURE, no encryption.
    return {
        "record": digest(b"elo.now/record-id/v1\0", bytes([seed])),
        "object": digest(b"elo.now/object-id/v1\0", ciphertext),
        "ciphertext": ciphertext,
        "targets": [(bytes([n]).hex() * 32, "07" * 32) for n in range(target_count)],
    }


def insert_rows(db: sqlite3.Connection, item: dict) -> None:
    """No commit and no dedup policy. Execute only the production INSERTs."""
    db.execute(SQL["insert_object"], (item["object"], item["ciphertext"], len(item["ciphertext"]), 100))
    db.execute(SQL["insert_record"], (item["record"], "dev.storage_fixture", None, None, None, 100))
    db.execute(SQL["insert_source"], (item["record"], item["object"]))
    for peer, mailbox in item["targets"]:
        db.execute(SQL["insert_target"], (item["record"], item["object"], peer, mailbox, 100))


@contextmanager
def transaction(db: sqlite3.Connection):
    db.execute("BEGIN IMMEDIATE")
    try:
        yield
        db.execute("COMMIT")
    except BaseException:
        if db.in_transaction:
            db.execute("ROLLBACK")
        raise


class RustSqlContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "client.sqlite"
        self.db = sqlite3.connect(self.path, isolation_level=None)
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA trusted_schema=OFF")
        self.db.executescript(MIGRATION)

    def tearDown(self):
        self.db.close()
        self.temp.cleanup()

    def store(self, item=None):
        item = item or sample()
        with transaction(self.db):
            insert_rows(self.db, item)
        return item

    def stats(self):
        return self.db.execute(SQL["stats"]).fetchone()

    def claim(self, at=100):
        with transaction(self.db):
            row = self.db.execute(SQL["list_due"], (at, 1)).fetchone()
            if row:
                _, obj, peer, mailbox, attempts, _ = row
                changed = self.db.execute(SQL["claim"], (obj, peer, mailbox, attempts)).rowcount
                self.assertEqual(changed, 1)
        return row

    def test_every_contract_file_is_embedded_in_rust(self):
        source = (ROOT / "crates/elo-core/src/store/mod.rs").read_text()
        self.assertEqual(len(SQL), 15)
        for name in SQL:
            self.assertIn(f'include_str!("sql/{name}.sql")', source)

    def test_commit_populates_four_tables_atomically(self):
        self.store()
        self.assertEqual(self.stats(), (1, 1, 1, 2, 0, 0, 0, 0))

    def test_rollback_on_second_delivery_leaves_nothing(self):
        self.db.executescript("""CREATE TEMP TRIGGER fail_second BEFORE INSERT ON main.outbox
            WHEN (SELECT count(*) FROM outbox)=1
            BEGIN SELECT RAISE(ABORT,'fixture failure'); END;""")
        with self.assertRaises(sqlite3.IntegrityError):
            self.store()
        self.assertEqual(self.stats(), (0,) * 8)

    def test_page_limit_disk_full_rolls_back(self):
        pages = self.db.execute("PRAGMA page_count").fetchone()[0]
        self.db.execute(f"PRAGMA max_page_count={pages}")
        item = sample()
        item["ciphertext"] = b"\xaa" * (2 * 1024 * 1024)
        item["object"] = digest(b"elo.now/object-id/v1\0", item["ciphertext"])
        with self.assertRaises(sqlite3.OperationalError) as caught:
            self.store(item)
        self.assertEqual(caught.exception.sqlite_errorcode, sqlite3.SQLITE_FULL)
        self.assertEqual(self.stats(), (0,) * 8)

    def test_commit_then_reopen_preserves_bytes_and_targets(self):
        item = self.store()
        self.db.close()
        self.db = sqlite3.connect(self.path, isolation_level=None)
        self.assertEqual(self.stats(), (1, 1, 1, 2, 0, 0, 0, 0))
        self.assertEqual(self.db.execute(SQL["get_object"], (item["object"],)).fetchone()[0], item["ciphertext"])

    def test_queries_provide_exact_retry_comparison(self):
        item = self.store()
        self.assertEqual(self.db.execute(SQL["get_record"], (item["record"],)).fetchone(),
                         ("dev.storage_fixture", None, None, None))
        self.assertEqual(self.db.execute(SQL["get_direct_sources"], (item["record"],)).fetchall(),
                         [(item["object"],)])
        self.assertEqual(self.db.execute(SQL["get_targets"], (item["object"],)).fetchall(), item["targets"])
        # Matching returned values is NOT proof that the Rust branch was executed.
        self.assertNotEqual(item["targets"], item["targets"][:-1])

    def test_conflicting_record_rolls_back_new_object(self):
        old = self.store()
        replacement = sample(2)
        replacement["record"] = old["record"]
        with self.assertRaises(sqlite3.IntegrityError):
            self.store(replacement)
        self.assertEqual(self.stats(), (1, 1, 1, 2, 0, 0, 0, 0))
        self.assertIsNone(self.db.execute(SQL["get_object"], (replacement["object"],)).fetchone())

    def test_source_binding_cannot_be_relabelled(self):
        item = self.store()
        with self.assertRaises(sqlite3.IntegrityError), transaction(self.db):
            self.db.execute(SQL["insert_record"], ("99" * 32, "dev.storage_fixture", None, None, None, 100))
            self.db.execute(SQL["insert_source"], ("99" * 32, item["object"]))
        self.assertEqual(self.stats()[1], 1)

    def test_stored_object_is_immutable(self):
        self.store()
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("UPDATE objects SET ciphertext=zeroblob(size_bytes)")

    def test_due_is_ordered_and_bounded(self):
        item = self.store()
        self.assertEqual(self.db.execute(SQL["list_due"], (99, 128)).fetchall(), [])
        rows = self.db.execute(SQL["list_due"], (100, 1)).fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0][2], rows[0][3]), item["targets"][0])

    def test_claim_only_one_target_and_increment_attempt(self):
        self.store()
        first = self.claim()
        self.assertEqual(self.stats()[3:5], (1, 1))
        row = self.db.execute("SELECT attempts FROM outbox WHERE object_id=? AND peer_id=? AND mailbox_id=?",
                              (first[1], first[2], first[3])).fetchone()
        self.assertEqual(row[0], 1)

    def test_retry_rejects_old_attempt_number(self):
        self.store(sample(target_count=1))
        old = self.claim()
        key = (old[1], old[2], old[3])
        self.assertEqual(self.db.execute(SQL["retry"], (*key, 1, 500, "TIMEOUT")).rowcount, 1)
        self.assertIsNone(self.claim(499))
        self.assertIsNotNone(self.claim(500))
        self.assertEqual(self.db.execute(SQL["retry"], (*key, 1, 600, "TIMEOUT")).rowcount, 0)
        self.assertEqual(self.db.execute(SQL["retry"], (*key, 2, 600, "TIMEOUT")).rowcount, 1)

    def test_restart_requeues_inflight_not_held(self):
        one = self.store(sample(1, 1))
        self.claim()
        two = self.store(sample(2, 1))
        self.db.execute(SQL["hold_record"], (two["record"],))
        self.db.execute(SQL["recover_inflight"])
        self.assertEqual(self.stats()[3:7], (1, 0, 0, 1))
        row = self.db.execute(SQL["list_due"], (0, 128)).fetchone()
        self.assertEqual((row[1], row[4]), (one["object"], 1))

    def test_hold_rejects_late_callback_and_preserves_object(self):
        item = self.store(sample(target_count=1))
        old = self.claim()
        self.db.execute(SQL["hold_record"], (item["record"],))
        self.assertEqual(self.db.execute(SQL["retry"], (old[1], old[2], old[3], 1, 100, "TIMEOUT")).rowcount, 0)
        self.assertEqual(self.db.execute(SQL["list_due"], (999, 128)).fetchall(), [])
        self.assertIsNotNone(self.db.execute(SQL["get_object"], (item["object"],)).fetchone())

    def test_one_placeholder_receipt_does_not_finish_other_targets(self):
        item = self.store()
        peer, mailbox = item["targets"][0]
        self.db.execute("UPDATE outbox SET state='STORED', receipt_record=X'00' WHERE peer_id=? AND mailbox_id=?",
                        (peer, mailbox))
        self.db.execute(SQL["hold_record"], (item["record"],))
        self.assertEqual(self.stats()[3:7], (0, 0, 1, 1))
        # Placeholder bytes only. No signed receipt is produced or verified.

    def test_zero_targets_is_local_only(self):
        self.store(sample(target_count=0))
        self.assertEqual(self.stats(), (1, 1, 1, 0, 0, 0, 0, 0))

    def test_schema_query_distinguishes_replica(self):
        expected = self.db.execute(SQL["schema"]).fetchall()
        other = sqlite3.connect(":memory:")
        try:
            other.executescript((ROOT / "migrations/001_replica.sql").read_text())
            self.assertNotEqual(expected, other.execute(SQL["schema"]).fetchall())
        finally:
            other.close()

    def test_schema_query_detects_extra_objects(self):
        expected = self.db.execute(SQL["schema"]).fetchall()
        self.db.execute("CREATE TABLE unrecognized(x)")
        self.assertNotEqual(expected, self.db.execute(SQL["schema"]).fetchall())

    def test_busy_transaction_does_not_insert_anything(self):
        other = sqlite3.connect(self.path, isolation_level=None)
        try:
            other.execute("BEGIN IMMEDIATE")
            self.db.execute("PRAGMA busy_timeout=1")
            with self.assertRaises(sqlite3.OperationalError) as caught:
                self.store()
            self.assertEqual(caught.exception.sqlite_errorcode, sqlite3.SQLITE_BUSY)
        finally:
            other.execute("ROLLBACK")
            other.close()
        self.assertEqual(self.stats(), (0,) * 8)

    def test_process_exit_before_and_after_exact_sql_commit(self):
        # Two fresh DBs and child processes. os._exit bypasses cleanup; this is
        # process-crash recovery, not simulation of OS/power failure.
        script = r'''
import os, sqlite3, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from test_rust_sql_contracts import MIGRATION, insert_rows, sample
c=sqlite3.connect(sys.argv[2], isolation_level=None)
c.execute('PRAGMA journal_mode=WAL'); c.execute('PRAGMA synchronous=FULL')
c.execute('PRAGMA foreign_keys=ON'); c.executescript(MIGRATION)
c.execute('BEGIN IMMEDIATE'); insert_rows(c,sample())
if sys.argv[3]=='after': c.execute('COMMIT')
os._exit(72 if sys.argv[3]=='after' else 71)
'''
        for mode, expected, code in [("before", 0, 71), ("after", 1, 72)]:
            path = Path(self.temp.name) / f"{mode}.sqlite"
            child = subprocess.run([sys.executable, "-c", script, str(ROOT / "tests"), str(path), mode],
                                   capture_output=True, timeout=15)
            self.assertEqual(child.returncode, code, child.stderr.decode())
            reopened = sqlite3.connect(path)
            try:
                self.assertEqual(reopened.execute(SQL["stats"]).fetchone(),
                                 (expected, expected, expected, 2 * expected, 0, 0, 0, 0))
            finally:
                reopened.close()


if __name__ == "__main__":
    unittest.main()
