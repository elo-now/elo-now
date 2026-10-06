#!/usr/bin/env python3
"""Start the relay without putting Firebase credentials in environment variables."""

import json
import os
from pathlib import Path


config = json.loads(Path('/etc/elo/wake/config.json').read_text())
if set(config) != {'public_url'}:
    raise SystemExit('Invalid wake configuration.')
os.execv('/usr/local/bin/elo-wake', [
    'elo-wake', '--service-account', '/etc/elo/wake/firebase.json',
    '--database', '/var/lib/elo-wake/wake.sqlite',
    '--listen', '127.0.0.1:8788', '--public-url', config['public_url'],
])
