#!/usr/bin/env python3
"""Apply the administration queue through a fixed, privileged service boundary.

The web process cannot access Docker or service keys. This worker only changes
the documented hosting policy and managed storage fields, never endpoint pins,
the witness journal, identities or message data.
"""
import argparse
import base64
import copy
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import time
import urllib.request

from schema import MAX_BODY, validate_configuration

ADMIN_UID = 21010
ROOT_UID = 0
MAX_JOB = MAX_BODY + 1024
JOB = re.compile(r"[0-9a-f]{32}\Z")


def read_file(path, maximum=1048576, uid=None):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as handle:
        metadata = os.fstat(handle.fileno())
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                or (uid is not None and (metadata.st_uid != uid or metadata.st_mode & 0o022))):
            raise ValueError('unsafe_file')
        content = handle.read(maximum + 1)
        if len(content) > maximum:
            raise ValueError('oversized_file')
        return content


def decode(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate_field')
            result[key] = value
        return result

    def invalid(_):
        raise ValueError('invalid_number')

    return json.loads(data, object_pairs_hook=unique, parse_constant=invalid)


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def remove(path):
    path.unlink(missing_ok=True)
    sync_directory(path.parent)


def atomic(path, data, uid=0, gid=0, mode=0o600):
    fd, name = tempfile.mkstemp(prefix='.admin-', dir=path.parent)
    try:
        os.fchmod(fd, mode)
        os.fchown(fd, uid, gid)
        with os.fdopen(fd, 'wb') as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, path)
        sync_directory(path.parent)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode()


class Worker:
    def __init__(self, settings):
        self.role = settings['role']
        if self.role not in ('api', 'witness'):
            raise ValueError('invalid_role')
        self.state_root = Path(settings['state_root'])
        self.admin = Path(settings['admin_root'])
        self.bundle = Path(settings['container_bundle'])
        self.version = settings['version']
        self.api_health_url = settings.get('api_health_url', 'http://127.0.0.1:18900/spaces/v1/health')
        if self.api_health_url not in ('http://127.0.0.1:18900/spaces/v1/health',
                                       'http://127.0.0.1:19900/spaces/v1/health'):
            raise ValueError('invalid_health_endpoint')
        for path in (self.state_root, self.admin, self.bundle):
            if (not path.is_absolute() or '..' in path.parts
                    or not re.fullmatch(r'/[A-Za-z0-9_./-]+', str(path))
                    or any(parent.is_symlink() for parent in (path, *path.parents))):
                raise ValueError('unsafe_path')
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', self.version):
            raise ValueError('invalid_version')
        self.transactions = self.admin / 'transactions'
        self.transactions.mkdir(mode=0o700, exist_ok=True)
        self.queue = self.admin / 'queue'
        self.status = self.admin / 'status'
        for path, uid in ((self.transactions, ROOT_UID), (self.status, ROOT_UID), (self.queue, ADMIN_UID)):
            metadata = path.lstat()
            if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != uid
                    or metadata.st_mode & 0o022):
                raise ValueError('unsafe_data_directory')

    def load(self, relative):
        return decode(read_file(self.state_root / relative))

    @contextmanager
    def queue_lock(self):
        fd = os.open(self.queue / '.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        try:
            metadata = os.fstat(fd)
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                    or metadata.st_uid not in (ROOT_UID, ADMIN_UID) or metadata.st_mode & 0o077):
                raise ValueError('unsafe_queue_lock')
            # The HTTP process also needs this lock; no restart/signing occurs while held.
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if metadata.st_uid != ADMIN_UID:
                os.fchown(fd, ADMIN_UID, ADMIN_UID)
            yield
        finally:
            os.close(fd)

    def completed(self, identifier):
        try:
            value = decode(read_file(self.status / (identifier + '.json'), 8192, ROOT_UID))
        except FileNotFoundError:
            return False
        if not isinstance(value, dict) or value.get('id') != identifier:
            raise ValueError('invalid_job_status')
        return value.get('status') in ('succeeded', 'failed')

    def state(self):
        if self.role == 'api':
            config = self.load('api/config/config.json')
            body = self.load('export/config/manifest-input.json')
            public = self.load('public/hosting-profile.json')
            storage = body.get('storage')
            managed = (storage or {}).get('managed')
            configuration = {
                'name': body['name'],
                'message_lifetimes': body['message_lifetimes'],
                'default_message_lifetime': body['default_message_lifetime'],
                'creation_mode': 'public' if config.get('allowed_creators') is None else 'allowlist',
                'allowed_creators': config.get('allowed_creators') or [],
                'managed_provider': managed['provider'] if managed else None,
                'storage_available': bool(storage and storage.get('url')),
            }
            hosting = {'link': public['link'], 'qr_url': '/hosting/hosting-qr.svg',
                       'revision': body['revision']}
        else:
            config = self.load('storage/config/config.json')
            value = self.load('storage/config/managed-storage.json') if config.get('managed_storage') else None
            provider = value['provider'] if value else {}
            kind = {'mega_folder': 'mega', 's3_compatible': 's3'}.get(provider.get('provider'))
            configuration = {'provider': kind, 'configured': bool(kind),
                             'allowed_owners': value['allowed_owners'] if value else []}
            if kind == 's3':
                configuration['public_fields'] = {'s3_' + key: provider[key]
                                                  for key in ('endpoint', 'region', 'bucket')}
            hosting = None
        return {'configuration': configuration, 'hosting': hosting}

    def refresh(self):
        atomic(self.admin / 'state.json', encoded(self.state()), gid=ADMIN_UID, mode=0o640)

    def final_status(self, identifier, status, error=None):
        value = {'id': identifier, 'status': status}
        if error:
            value['error'] = error
        atomic(self.status / (identifier + '.json'), encoded(value), gid=ADMIN_UID, mode=0o640)

    def compose(self, arguments):
        result = subprocess.run([
            'docker', 'compose', '--env-file', str(self.state_root / 'compose.env'),
            '-f', str(self.bundle / ('compose.' + self.role + '.yaml')), *arguments,
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=100)
        if result.returncode:
            raise ValueError('service_restart_failed')

    def restart(self):
        service = 'api' if self.role == 'api' else 'storage'
        self.compose(['restart', service])
        url = (self.api_health_url if self.role == 'api'
               else 'http://127.0.0.1:17846/health')
        expected_status = 200 if self.role == 'api' else 204
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                with opener.open(url, timeout=2) as reply:
                    if reply.status == expected_status:
                        return
            except OSError:
                pass
            time.sleep(.3)
        raise ValueError('service_health_failed')

    def sign(self, body):
        stage = Path(tempfile.mkdtemp(prefix='sign-', dir=self.transactions))
        os.chown(stage, 21005, 21005)
        try:
            atomic(stage / 'input.json', encoded(body), 21005, 21005)
            subprocess.run([
                'docker', 'run', '--rm', '--pull', 'never', '--network', 'none', '--read-only',
                '--user', '21005:21005', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
                '--pids-limit', '64', '--memory', '128m', '--memory-swap', '128m', '--ulimit', 'core=0',
                '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=8m,mode=0700,uid=21005,gid=21005',
                '--mount', f'type=bind,src={stage},dst=/work',
                '--mount', f'type=bind,src={self.state_root}/export/config/signing-key.bin,dst=/key,readonly',
                'elo-api:' + self.version, 'elo-team', 'hosting-config', '--input', '/work/input.json',
                '--key', '/key', '--output', '/work/profile.json', '--qr-output', '/work/qr.svg',
            ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
            public = decode(read_file(stage / 'profile.json'))
            if set(public) != {'record', 'link'} or not public['link'].startswith('elo://hosting/v1#'):
                raise ValueError('invalid_signed_profile')
            qr = read_file(stage / 'qr.svg')
            if b'<svg' not in qr or b'</svg>' not in qr:
                raise ValueError('invalid_qr')
            return public, qr
        finally:
            shutil.rmtree(stage)

    def api_changes(self, value):
        config = self.load('api/config/config.json')
        body = self.load('export/config/manifest-input.json')
        if value['managed_provider'] and not ((body.get('storage') or {}).get('url')):
            raise ValueError('storage_unavailable')
        config['allowed_creators'] = None if value['creation_mode'] == 'public' else value['allowed_creators']
        config['allowed_message_retentions'] = value['message_lifetimes']
        body['name'] = value['name']
        body['message_lifetimes'] = value['message_lifetimes']
        body['default_message_lifetime'] = value['default_message_lifetime']
        body['revision'] += 1
        if body.get('storage'):
            body['storage']['managed'] = ({'provider': value['managed_provider'], 'retention_hours': 1}
                                          if value['managed_provider'] else None)
        public, qr = self.sign(body)
        # The public page references the current generated SVG and link; no provider secret is exported.
        import importlib.util
        spec = importlib.util.spec_from_file_location('hosting_export', self.bundle / 'export.py')
        exporter = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(exporter)
        return [
            ('api/config/config.json', encoded(config), 21001, 0o600),
            ('export/config/manifest-input.json', encoded(body), 21005, 0o600),
            ('public/hosting-profile.json', encoded(public), 0, 0o644),
            ('public/hosting-link.txt', (public['link'] + '\n').encode(), 0, 0o644),
            ('public/hosting-qr.svg', qr, 0, 0o644),
            ('public/hosting-profile.html', exporter.hosting_page(public['link']), 0, 0o644),
        ]

    def storage_changes(self, value):
        config = self.load('storage/config/config.json')
        if value['provider'] is None:
            config.pop('managed_storage', None)
            return [('storage/config/config.json', encoded(config), 21003, 0o600),
                    ('storage/config/managed-storage.json', None, 21003, 0o600)]
        previous = self.load('storage/config/managed-storage.json') if config.get('managed_storage') else {}
        kind = {'mega': 'mega_folder', 's3': 's3_compatible'}[value['provider']]
        previous_provider = previous.get('provider', {})
        provider = copy.deepcopy(previous_provider) if previous_provider.get('provider') == kind else {'provider': kind}
        fields = {'folder_link': 'folder_link', 'write_auth': 'write_auth'} if kind == 'mega_folder' else {
            's3_' + key: key for key in ('endpoint', 'region', 'bucket', 'access_key', 'secret_key')}
        for source, target in fields.items():
            if value.get(source):
                provider[target] = value[source]
        if set(provider) != {'provider', *fields.values()} or not all(provider.values()):
            raise ValueError('provider_credentials_required')
        complete = {'provider': value['provider'], 'allowed_owners': value['allowed_owners']}
        complete.update({source: provider[target] for source, target in fields.items()})
        validate_configuration('witness', complete)
        if kind == 'mega_folder':
            environment = read_file(self.state_root / 'compose.env').decode()
            if 'ELO_STORAGE_IMAGE=elo-storage-mega' not in environment.splitlines():
                raise ValueError('mega_adapter_unavailable')
        managed = {'provider': provider, 'allowed_owners': value['allowed_owners']}
        config['managed_storage'] = '/etc/elo/storage/managed-storage.json'
        return [('storage/config/managed-storage.json', encoded(managed), 21003, 0o600),
                ('storage/config/config.json', encoded(config), 21003, 0o600)]

    def apply(self, identifier, value):
        current = self.state()['configuration']
        if self.role == 'api' and all(current.get(k) == v for k, v in value.items()):
            self.refresh()
            self.final_status(identifier, 'succeeded')
            return
        changes = self.api_changes(value) if self.role == 'api' else self.storage_changes(value)
        previous = []
        for name, _, _, _ in changes:
            path = self.state_root / name
            if path.exists() or path.is_symlink():
                data = read_file(path)
                meta = path.stat()
                previous.append({'path': name, 'content': base64.b64encode(data).decode(),
                                 'uid': meta.st_uid, 'gid': meta.st_gid, 'mode': stat.S_IMODE(meta.st_mode)})
            else:
                previous.append({'path': name, 'content': None})
        transaction = {'id': identifier, 'phase': 'prepared', 'previous': previous}
        journal = self.transactions / (identifier + '.json')
        atomic(journal, encoded(transaction))
        try:
            for name, data, uid, mode in changes:
                path = self.state_root / name
                if data is None:
                    remove(path)
                else:
                    atomic(path, data, uid, uid, mode)
            self.restart()
            transaction['phase'] = 'committed'
            atomic(journal, encoded(transaction))
            self.refresh()
            self.final_status(identifier, 'succeeded')
            remove(journal)
        except Exception:
            # Once committed, a later state/status write failure must never roll
            # back configuration or turn a successful retry into a failed job.
            if not self.recover(journal):
                raise

    def recover(self, journal):
        transaction = decode(read_file(journal, maximum=8 * 1048576, uid=ROOT_UID))
        if not isinstance(transaction, dict) or set(transaction) != {'id', 'phase', 'previous'}:
            raise ValueError('invalid_transaction')
        identifier = transaction['id']
        if (not isinstance(identifier, str) or not JOB.fullmatch(identifier)
                or journal.name != identifier + '.json' or transaction['phase'] not in ('prepared', 'committed')):
            raise ValueError('invalid_transaction')
        allowed = ({'api/config/config.json', 'export/config/manifest-input.json',
                    'public/hosting-profile.json', 'public/hosting-link.txt',
                    'public/hosting-qr.svg', 'public/hosting-profile.html'} if self.role == 'api'
                   else {'storage/config/config.json', 'storage/config/managed-storage.json'})
        previous = transaction['previous']
        if not isinstance(previous, list) or len(previous) != len(allowed):
            raise ValueError('invalid_transaction')
        restored, seen = [], set()
        for record in previous:
            if (not isinstance(record, dict) or not isinstance(record.get('path'), str)
                    or record['path'] not in allowed or record['path'] in seen):
                raise ValueError('invalid_transaction_path')
            seen.add(record['path'])
            if record.get('content') is None:
                if set(record) != {'path', 'content'}:
                    raise ValueError('invalid_transaction')
                restored.append((record['path'], None, None, None, None))
            else:
                if (set(record) != {'path', 'content', 'uid', 'gid', 'mode'}
                        or any(type(record[key]) is not int or not 0 <= record[key] <= 4294967295 for key in ('uid', 'gid'))
                        or type(record['mode']) is not int or not 0 <= record['mode'] <= 0o777
                        or not isinstance(record['content'], str)):
                    raise ValueError('invalid_transaction')
                data = base64.b64decode(record['content'], validate=True)
                if len(data) > 1048576:
                    raise ValueError('oversized_transaction')
                restored.append((record['path'], data, record['uid'], record['gid'], record['mode']))
        if transaction['phase'] == 'committed':
            self.refresh()
            self.final_status(identifier, 'succeeded')
        else:
            for name, data, uid, gid, mode in restored:
                path = self.state_root / name
                if data is None:
                    remove(path)
                else:
                    atomic(path, data, uid, gid, mode)
            self.restart()
            self.refresh()
            self.final_status(identifier, 'failed', 'configuration_not_applied')
        remove(journal)
        return transaction['phase'] == 'committed'

    def run(self):
        for path in self.transactions.glob('*.json'):
            self.recover(path)
        self.refresh()
        with self.queue_lock():
            jobs = sorted(path for path in self.queue.glob('*.json') if JOB.fullmatch(path.stem))
            if len(jobs) > 1024:
                raise ValueError('oversized_queue')
        for job in jobs:
            identifier = job.stem
            if not JOB.fullmatch(identifier):
                continue
            try:
                with self.queue_lock():
                    if self.completed(identifier):
                        remove(job)
                        continue
                    request = decode(read_file(job, maximum=MAX_JOB, uid=ADMIN_UID))
                if (not isinstance(request, dict) or set(request) != {'v', 'id', 'role', 'created_at', 'configuration'}
                        or type(request['v']) is not int or request['v'] != 1
                        or request['id'] != identifier or request['role'] != self.role
                        or type(request['created_at']) is not int
                        or not 0 <= time.time() - request['created_at'] <= 3600):
                    raise ValueError('invalid_job')
                value = validate_configuration(self.role, request['configuration'])
                self.apply(identifier, value)
            except BlockingIOError:
                raise  # Retry contention; it is not a failed configuration request.
            except Exception:
                # No provider output, credentials or operator input reaches the status file/journal.
                if (self.transactions / (identifier + '.json')).exists():
                    raise RuntimeError('configuration_recovery_required') from None
                if not self.completed(identifier):
                    self.final_status(identifier, 'failed', 'configuration_not_applied')
            finally:
                with self.queue_lock():
                    if self.completed(identifier):
                        remove(job)
        # Keep status history bounded; statuses contain no configuration or secrets.
        for path in self.status.glob('*.json'):
            metadata = path.lstat()
            if (JOB.fullmatch(path.stem) and stat.S_ISREG(metadata.st_mode) and metadata.st_uid == ROOT_UID
                    and metadata.st_nlink == 1 and time.time() - metadata.st_mtime > 86400):
                remove(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--refresh-state', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('Run the fixed worker as root.')
    settings = decode(read_file(args.config, maximum=16384, uid=ROOT_UID))
    worker = Worker(settings)
    fd = os.open('/run/elo-admin-apply.lock', os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    with os.fdopen(fd, 'wb') as lock:
        metadata = os.fstat(lock.fileno())
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                or metadata.st_uid != ROOT_UID or metadata.st_mode & 0o077):
            raise ValueError('unsafe_worker_lock')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        worker.refresh() if args.refresh_state else worker.run()


if __name__ == '__main__':
    try:
        main()
    except BlockingIOError:
        raise SystemExit(0) from None  # Another worker or a short HTTP enqueue owns the lock.
    except Exception:
        raise SystemExit('Hosting configuration could not be applied.') from None
