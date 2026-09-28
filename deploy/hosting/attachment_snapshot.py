"""Bounded ciphertext copies from the loopback-only hosting operator listener."""
import hashlib
import json
from pathlib import Path
import re
import shutil
import time
import urllib.error
import urllib.request
import urllib.parse
from online_snapshot import SourceChanged

HEX64 = re.compile(r'[0-9a-f]{64}\Z')
HEX32 = re.compile(r'[0-9a-f]{32}\Z')
MAX_MANIFEST = 8 * 1024 * 1024
MAX_FILE = 6 * 1024 * 1024


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        raise ValueError('Backup endpoint must not redirect')


class AttachmentSnapshot:
    def __init__(self, config):
        self.base = config['operator_url'].rstrip('/')
        url = urllib.parse.urlsplit(self.base)
        if (url.scheme != 'http' or url.hostname not in ('127.0.0.1', '::1')
                or url.username or url.password or url.query or url.fragment or url.path):
            raise ValueError('Expected a loopback operator origin')
        self.maximum = config.get('max_bytes', 1024 * 1024 * 1024)
        if type(self.maximum) is not int or not 1 <= self.maximum <= 8 * 1024**3:
            raise ValueError('Invalid attachment backup byte budget')
        self.deadline = time.monotonic() + 600
        self.http = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def request(self, path):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('Attachment backup exceeded its time budget')
        try:
            return self.http.open(self.base + path, timeout=min(30, remaining))
        except urllib.error.HTTPError as error:
            if error.code in (404, 410, 503):
                raise SourceChanged('Attachment source is busy or changed') from None
            raise

    def inventory(self):
        with self.request('/backup/attachments') as response:
            raw = bytearray()
            while len(raw) <= MAX_MANIFEST:
                if time.monotonic() > self.deadline:
                    raise TimeoutError('Attachment inventory exceeded its time budget')
                chunk = response.read1(min(65536, MAX_MANIFEST + 1 - len(raw)))
                if not chunk:
                    break
                raw.extend(chunk)
        if len(raw) > MAX_MANIFEST:
            raise ValueError('Attachment inventory is too large')
        value = json.loads(raw)
        if value.get('version') != 1 or not isinstance(value.get('spaces'), dict):
            raise ValueError('Invalid attachment inventory')
        total = 0
        for space, state in value['spaces'].items():
            if not HEX64.fullmatch(space) or not HEX64.fullmatch(state.get('revision', '')):
                raise ValueError('Invalid Space in attachment inventory')
            if not isinstance(state.get('objects'), list):
                raise ValueError('Invalid attachment object inventory')
            seen = set()
            for entry in state['objects']:
                obj, size = entry.get('object', ''), entry.get('size')
                if (not HEX32.fullmatch(obj) or obj in seen
                        or type(size) is not int or not 0 < size <= MAX_FILE
                        or not HEX64.fullmatch(entry.get('sha256', ''))):
                    raise ValueError('Invalid attachment metadata')
                seen.add(obj)
                total += size
        if total > self.maximum:
            raise ValueError('Attachment backup exceeds its byte budget')
        return value, total

    def capture(self, destination):
        manifest, total = self.inventory()
        if shutil.disk_usage(destination).free < total + 2 * 1024**3:
            raise OSError('Insufficient free disk for attachment backup')
        target = destination / 'elo-attachments'
        target.mkdir(mode=0o700)
        for space, state in manifest['spaces'].items():
            for entry in state['objects']:
                obj, expected = entry['object'], entry['size']
                folder = target / 'spaces' / space
                folder.mkdir(parents=True, exist_ok=True, mode=0o700)
                digest, size = hashlib.sha256(), 0
                with self.request(f'/backup/attachments/{space}/{obj}') as response:
                    with (folder / obj).open('xb') as output:
                        while True:
                            if time.monotonic() > self.deadline:
                                raise TimeoutError('Attachment backup exceeded its time budget')
                            chunk = response.read1(min(65536, expected - size + 1))
                            if not chunk:
                                break
                            size += len(chunk)
                            if size > expected:
                                raise ValueError('Attachment exceeds its declared size')
                            digest.update(chunk)
                            output.write(chunk)
                if size != expected or digest.hexdigest() != entry['sha256']:
                    raise ValueError('Attachment backup failed integrity validation')
        (target / 'manifest.json').write_text(json.dumps(manifest, sort_keys=True))
        return manifest

    def verify_unchanged(self, before):
        after, _ = self.inventory()
        if before != after:
            raise SourceChanged('Attachment metadata changed during capture')
