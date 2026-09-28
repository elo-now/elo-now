"""Consistent, bounded snapshots of SQLite databases and adjacent state files.

SQLite's online backup API includes committed WAL data. Persistent observer
connections and a second file inventory reject a capture that overlaps writes,
replacement or deletion. A busy source fails safely instead of stopping services
or publishing a mixed snapshot. No remote attachment bytes are included.
"""
from contextlib import ExitStack, closing
import hashlib
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import time


class SourceChanged(RuntimeError):
    pass


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def inventory(paths):
    entries = {}
    for root in map(Path, paths):
        for path in [root, *sorted(root.rglob('*'))] if root.is_dir() else [root]:
            info = path.lstat()
            mode = stat.S_IMODE(info.st_mode)
            if path.is_symlink():
                entries[path] = ('link', mode, os.readlink(path))
            elif path.is_dir():
                entries[path] = ('directory', mode)
            elif path.is_file():
                with path.open('rb') as stream:
                    database = stream.read(16) == b'SQLite format 3\0'
                entries[path] = (('sqlite', mode, info.st_dev, info.st_ino) if database
                                 else ('file', mode, digest(path)))
            else:
                raise ValueError('Unsupported backup file type')
    # Never copy WAL files over a self-contained SQLite backup on restore.
    for path, entry in list(entries.items()):
        if entry[0] == 'sqlite':
            for suffix in ('-wal', '-shm', '-journal'):
                entries.pop(Path(str(path) + suffix), None)
    return entries


def capture(paths, destination, timeout=120):
    deadline = time.monotonic() + timeout

    def check_deadline(*_):
        if time.monotonic() > deadline:
            raise TimeoutError('Online snapshot exceeded its time budget')

    before = inventory(paths)
    with ExitStack() as stack:
        observers = {}
        # Establish every observer before copying any database.
        for path, entry in before.items():
            check_deadline()
            if entry[0] == 'sqlite':
                db = stack.enter_context(closing(sqlite3.connect(
                    path.as_uri() + '?mode=ro', uri=True, timeout=1)))
                db.execute('PRAGMA query_only=ON')
                observers[path] = (db, db.execute('PRAGMA data_version').fetchone())
        for path, entry in before.items():
            check_deadline()
            target = destination / str(path).lstrip('/')
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if entry[0] == 'directory':
                target.mkdir(exist_ok=True, mode=0o700)
            elif entry[0] == 'link':
                target.symlink_to(entry[2])
            elif entry[0] == 'sqlite':
                with closing(sqlite3.connect(target)) as output:
                    observers[path][0].backup(output, pages=256,
                                             progress=check_deadline, sleep=0.05)
                    output.execute('PRAGMA journal_mode=DELETE')
                    if output.execute('PRAGMA quick_check').fetchall() != [('ok',)]:
                        raise RuntimeError('Snapshot database failed validation')
            else:
                shutil.copyfile(path, target, follow_symlinks=False)
                if digest(target) != entry[2]:
                    raise SourceChanged('File changed during capture')
            if entry[0] != 'link':
                target.chmod(entry[1])
        if before != inventory(paths):
            raise SourceChanged('Backup file inventory changed during capture')
        for db, version in observers.values():
            if db.execute('PRAGMA data_version').fetchone() != version:
                raise SourceChanged('Database changed during capture')
        check_deadline()
