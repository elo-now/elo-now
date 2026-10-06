#!/usr/bin/env python3
"""Start the relay without putting Firebase credentials in environment variables."""

import json
import os
import argparse
from pathlib import Path


def command(directory, listen):
    config = json.loads((directory / 'config.json').read_text())
    if set(config) != {'public_url'}:
        raise ValueError('Invalid wake configuration.')
    result = [
        'elo-wake', '--service-account', str(directory / 'firebase.json'),
        '--database', '/var/lib/elo-wake/wake.sqlite',
        '--listen', listen, '--public-url', config['public_url'],
    ]
    # The relay validates ownership, permissions and key syntax itself. A bad
    # installed key must fail startup instead of silently disabling VoIP pushes.
    apns = directory / 'apns.json'
    if apns.exists():
        result += ['--apns', str(apns)]
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--listen', default='127.0.0.1:8788')
    args = parser.parse_args()
    os.execv('/usr/local/bin/elo-wake', command(Path('/etc/elo/wake'), args.listen))
