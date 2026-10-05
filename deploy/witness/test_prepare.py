"""File safety regressions; these tests never create users or touch /etc."""

import importlib.util
import os
from pathlib import Path
import tempfile
import unittest


spec = importlib.util.spec_from_file_location("prepare", Path(__file__).with_name("prepare.py"))
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)


class PreparationFiles(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.uid = os.getuid()
        self.gid = os.getgid()

    def test_repeated_key_preparation_preserves_existing_bytes_and_inode(self):
        path = self.root / "key"
        first = prepare.secret(path, self.uid, self.gid)
        inode = path.stat().st_ino
        self.assertEqual(32, len(first))
        self.assertEqual(first, prepare.secret(path, self.uid, self.gid))
        self.assertEqual(inode, path.stat().st_ino)
        self.assertEqual(0o600, path.stat().st_mode & 0o777)

    def test_exclusive_creation_never_overwrites_an_existing_key(self):
        path = self.root / "key"
        first = prepare.secret(path, self.uid, self.gid)
        with self.assertRaises(FileExistsError):
            prepare.create_private(path, b"replacement", self.uid, self.gid)
        self.assertEqual(first, path.read_bytes())

    def test_symbolic_and_hard_linked_keys_are_rejected(self):
        path = self.root / "key"
        prepare.secret(path, self.uid, self.gid)
        symbolic = self.root / "symbolic"
        symbolic.symlink_to(path)
        with self.assertRaises(RuntimeError):
            prepare.secret(symbolic, self.uid, self.gid)
        hard = self.root / "hard"
        os.link(path, hard)
        with self.assertRaises(RuntimeError):
            prepare.secret(hard, self.uid, self.gid)

    def test_wrong_size_and_permissions_fail_without_replacing_the_file(self):
        path = self.root / "key"
        prepare.create_private(path, b"short", self.uid, self.gid)
        with self.assertRaises(RuntimeError):
            prepare.secret(path, self.uid, self.gid)
        self.assertEqual(b"short", path.read_bytes())
        path.chmod(0o644)
        with self.assertRaises(RuntimeError):
            prepare.read_private(path, self.uid, self.gid, 32)
        self.assertEqual(0o644, path.stat().st_mode & 0o777)

    def test_public_derivation_matches_ed25519_zero_seed_vector(self):
        self.assertEqual(
            "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29",
            prepare.public_key(bytes(32)),
        )


if __name__ == "__main__":
    unittest.main()
