#!/usr/bin/env python3
"""Manually activate this witness process using an independently trusted anchor."""

import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

HEX = re.compile(r"[0-9a-f]{64}\Z")


def require(value, message):
    if not value:
        raise ValueError(message)


def activation(startup, anchor, first_bootstrap=False, now_ms=None):
    require(set(anchor) == {"expected_position", "public_key", "key_generation"},
            "Anchor must contain expected_position, public_key and key_generation only.")
    position = anchor["expected_position"]
    require(isinstance(position, dict) and set(position) == {"sequence", "record_id"}, "Invalid anchor position.")
    sequence, record_id = position["sequence"], position["record_id"]
    require(type(sequence) is int and 0 <= sequence <= 2**64 - 1, "Invalid anchor sequence.")
    require((sequence == 0 and record_id is None) or
            (sequence > 0 and isinstance(record_id, str) and HEX.fullmatch(record_id)), "Invalid anchor record ID.")
    require(sequence != 0 or first_bootstrap, "Zero requires explicit --first-bootstrap for a never-used deployment.")
    require(not first_bootstrap or sequence == 0, "First bootstrap requires an independently confirmed empty deployment.")
    require(isinstance(anchor["public_key"], str) and HEX.fullmatch(anchor["public_key"]), "Invalid public key.")
    require(type(anchor["key_generation"]) is int and 0 < anchor["key_generation"] <= 2**64 - 1,
            "Invalid key generation.")
    require(anchor["public_key"] == startup["public_key"] and anchor["key_generation"] == startup["key_generation"],
            "Independent pin does not match this process.")
    require(position == startup["observed_position"], "External anchor differs from the journal; recovery is required.")
    require(isinstance(startup["startup_nonce"], str) and HEX.fullmatch(startup["startup_nonce"]), "Invalid startup nonce.")
    now_ms = int(time.time() * 1000) if now_ms is None else now_ms
    return {"startup_nonce": startup["startup_nonce"], "expected_position": position,
            "public_key": anchor["public_key"], "key_generation": anchor["key_generation"],
            "expires_at_ms": now_ms + 300000}


def install(document, runtime):
    info = runtime.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
            "Runtime must be a private directory owned by this service.")
    destination = runtime / "activation.json"
    require(not destination.exists() and not destination.is_symlink(), "An activation file already exists.")
    temporary = runtime / (".activation-" + os.urandom(12).hex())
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(document, stream)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        # An atomic no-replace link avoids overwriting a concurrent manual activation.
        os.link(temporary, destination, follow_symlinks=False)
    finally:
        temporary.unlink(missing_ok=True)
    fd = os.open(runtime, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--anchor-stdin", action="store_true", required=True,
                        help="Read a separately verified external anchor, never startup.json.")
    parser.add_argument("--first-bootstrap", action="store_true",
                        help="Confirm this is a never-used deployment, not a restored or reset journal.")
    args = parser.parse_args()
    os.umask(0o077)
    runtime = Path("/run/elo-witness")
    path = runtime / "startup.json"
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) == 0o600, "Unsafe startup file.")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd) as stream:
        startup = json.loads(stream.read(4097))
    raw_anchor = sys.stdin.buffer.read(4097)
    require(len(raw_anchor) <= 4096, "Oversized anchor.")
    document = activation(startup, json.loads(raw_anchor), args.first_bootstrap)
    install(document, runtime)
    print("Activation submitted for this process; verify local /readyz. No external anchor was advanced.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError) as error:
        sys.exit(str(error))
