#!/usr/bin/env python3
"""Bounded MEGAcmd folder adapter. Secrets arrive only through a private pipe.

Each operation has a separate volatile HOME and Unix socket. No account login,
public WebDAV listener, persistent session, shell history or arbitrary command
is accepted. The service unit must provide /run/elo-storage on tmpfs.
"""
import base64
import contextlib
import ctypes
import json
import os
from pathlib import Path
import re
import resource
import secrets
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time

MAX_BYTES = 6 * 1024 * 1024
MAX_INPUT = 9 * 1024 * 1024
MAX_REPLY = 256 * 1024
FOLDER = re.compile(r"https://mega\.nz/folder/[A-Za-z0-9_-]{8}#[A-Za-z0-9_-]{22,64}\Z")
AUTH = re.compile(r"[A-Za-z0-9_-]{16,128}\Z")
SEGMENT = re.compile(r"[0-9a-f]{16,128}\Z")


class StorageError(Exception):
    pass


def validate(request):
    if not isinstance(request, dict) or set(request) - {'op', 'folder_link', 'write_auth', 'space', 'object', 'data'}:
        raise StorageError('invalid_request')
    if request.get('op') not in ('probe', 'put', 'get', 'delete'):
        raise StorageError('invalid_operation')
    if not FOLDER.fullmatch(request.get('folder_link', '')) or not AUTH.fullmatch(request.get('write_auth', '')):
        raise StorageError('invalid_folder_credentials')
    if request['op'] != 'probe':
        if not SEGMENT.fullmatch(request.get('space', '')) or not SEGMENT.fullmatch(request.get('object', '')):
            raise StorageError('invalid_object')
    if request['op'] == 'put':
        try:
            raw = base64.b64decode(request.get('data', ''), validate=True)
        except (ValueError, TypeError):
            raise StorageError('invalid_object') from None
        if len(raw) > MAX_BYTES:
            raise StorageError('object_too_large')
        return raw
    return None


def exact(sock, size):
    chunks = bytearray()
    while len(chunks) < size:
        part = sock.recv(size - len(chunks))
        if not part:
            raise StorageError('provider_protocol')
        chunks.extend(part)
    return bytes(chunks)


def execute(path, command):
    # MEGAcmd 2.6 POSIX IPC: native int result, partial output is size_t framed.
    # Command comes exclusively from fixed templates with validated arguments.
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(75)
        sock.connect(str(path))
        sock.sendall(command.encode('ascii'))
        result = struct.unpack('=i', exact(sock, 4))[0]
        consumed = 0
        while result in (-62, -63):
            length = struct.unpack('@N', exact(sock, struct.calcsize('@N')))[0]
            consumed += length
            if consumed > MAX_REPLY:
                raise StorageError('provider_output_limit')
            exact(sock, length)  # Never relay provider output: it may contain keys.
            result = struct.unpack('=i', exact(sock, 4))[0]
        if result in (-60, -61):
            raise StorageError('provider_interaction_required')
        while True:
            part = sock.recv(8192)
            if not part:
                break
            consumed += len(part)
            if consumed > MAX_REPLY:
                raise StorageError('provider_output_limit')
        return result


def checked(path, command, allowed=(0,)):
    code = execute(path, command)
    if code not in allowed:
        # Only the numeric error class is exposed, never the provider response.
        if code in (-53, -9):
            raise StorageError('not_found')
        raise StorageError('provider_rejected')


def child_limits(parent):
    # The Rust wrapper may kill a stalled helper. Do not leave its daemon alive.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent:
        os._exit(1)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    # Bounds a replaced remote file and session cache before any download starts.
    resource.setrlimit(resource.RLIMIT_FSIZE, (8 * 1024 * 1024, 8 * 1024 * 1024))


def runtime_root():
    root = Path('/run/elo-storage/mega')
    if root.resolve() != root:
        raise StorageError('unsafe_runtime')
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    meta = root.lstat()
    if root.resolve(strict=True) != root or not stat.S_ISDIR(meta.st_mode) or meta.st_uid != os.getuid() or meta.st_mode & 0o077:
        raise StorageError('unsafe_runtime')
    # Session secrets must not silently fall back to persistent storage.
    mounts = [line.split() for line in Path('/proc/mounts').read_text().splitlines()]
    candidates = [m for m in mounts if str(root) == m[1] or str(root).startswith(m[1].rstrip('/') + '/')]
    if not candidates or max(candidates, key=lambda m: len(m[1]))[2] != 'tmpfs':
        raise StorageError('volatile_runtime_required')
    # SIGKILL cannot execute finally. Reap only our stale operation directories;
    # every live operation has a hard 70-second deadline, well below ten minutes.
    cutoff = time.time() - 600
    for entry in root.iterdir():
        meta = entry.lstat()
        if (entry.name.startswith('op-') and stat.S_ISDIR(meta.st_mode)
                and meta.st_uid == os.getuid() and meta.st_mtime < cutoff):
            shutil.rmtree(entry)
    return root


def operate(request):
    raw = validate(request)
    root = runtime_root()
    with tempfile.TemporaryDirectory(prefix='op-', dir=root) as home:
        directory = Path(home)
        runtime = directory / '.megaCmd'
        runtime.mkdir(mode=0o700)
        ipc = runtime / 'megacmd.socket'
        if len(str(ipc)) >= 100:
            raise StorageError('unsafe_runtime')
        env = {'PATH': '/usr/bin:/bin', 'HOME': home, 'LANG': 'C.UTF-8'}
        helper_pid = os.getpid()
        daemon = subprocess.Popen(['/usr/bin/mega-cmd-server', '--debug=0'], env=env,
                                  stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL, start_new_session=True,
                                  preexec_fn=lambda: child_limits(helper_pid))
        try:
            until = time.monotonic() + 10
            while not ipc.exists():
                if daemon.poll() is not None or time.monotonic() > until:
                    raise StorageError('provider_unavailable')
                time.sleep(.05)
            checked(ipc, 'login ' + request['folder_link'] + ' --auth-key=' + request['write_auth'])
            if request['op'] == 'probe':
                token = secrets.token_hex(16)
                name = '/elo-probe-' + token
                payload = secrets.token_bytes(32)
                source = directory / 'probe'; source.write_bytes(payload)
                try:
                    checked(ipc, f'put {source} {name}')
                    target = directory / 'download'
                    checked(ipc, f'get {name} {target}')
                    if target.read_bytes() != payload:
                        raise StorageError('provider_integrity')
                finally:
                    checked(ipc, f'rm -f {name}', (0, -53, -9))
                return {'ok': True}
            parent = '/elo/' + request['space']
            remote = parent + '/' + request['object']
            if request['op'] == 'put':
                checked(ipc, 'mkdir -p ' + parent, (0, -64))
                source = directory / 'upload'; source.write_bytes(raw)
                checked(ipc, f'put {source} {remote}')
                return {'ok': True}
            if request['op'] == 'get':
                target = directory / 'download'
                checked(ipc, f'get {remote} {target}')
                meta = target.lstat()
                if not stat.S_ISREG(meta.st_mode) or meta.st_size > MAX_BYTES:
                    raise StorageError('object_too_large')
                return {'ok': True, 'data': base64.b64encode(target.read_bytes()).decode('ascii')}
            checked(ipc, 'rm -f ' + remote, (0, -53, -9))
            return {'ok': True}
        finally:
            # No session is retained on disk or across operations. This never
            # logs out a user's unrelated MEGA client or touches other folders.
            with contextlib.suppress(ProcessLookupError):
                os.killpg(daemon.pid, signal.SIGTERM)
            try:
                daemon.wait(timeout=3)
            except subprocess.TimeoutExpired:
                pass
            # Also kill descendants after a leader that exited on its own.
            with contextlib.suppress(ProcessLookupError):
                os.killpg(daemon.pid, signal.SIGKILL)
            if daemon.poll() is None:
                with contextlib.suppress(subprocess.TimeoutExpired):
                    daemon.wait(timeout=3)


def stop(signum, frame):
    raise StorageError('operation_cancelled')


def main():
    os.umask(0o077)
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGALRM, stop)
    signal.alarm(70)
    try:
        payload = sys.stdin.buffer.read(MAX_INPUT + 1)
        if len(payload) > MAX_INPUT:
            raise StorageError('request_too_large')
        result = operate(json.loads(payload))
    except StorageError as error:
        result = {'ok': False, 'error': str(error)}
    except Exception:
        result = {'ok': False, 'error': 'provider_unavailable'}
    finally:
        signal.alarm(0)
    print(json.dumps(result, separators=(',', ':')))


if __name__ == '__main__':
    main()
