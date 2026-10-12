#!/usr/bin/env python3
"""Pin a hosting registration key on a stopped witness; never start or unseal it."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import urlsplit


def registration(host, public_key):
    if not isinstance(host, str) or not isinstance(public_key, str):
        raise ValueError("Expected a hosting URL and public signing key")
    parsed = urlsplit(host)
    name = parsed.hostname or ""
    # Operational pins use explicit HTTPS origins; localhost is for unit tests only.
    labels = name.split(".")
    if (not re.fullmatch(r"https://[a-z0-9.-]+(?::[1-9][0-9]{0,4})?/spaces/v1/create", host)
            or len(labels) < 2 or len(name) > 253
            or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels)
            or all(label.isdigit() for label in labels)
            or (parsed.port is not None and parsed.port > 65535)
            or not re.fullmatch(r"[0-9a-f]{64}", public_key)):
        raise ValueError("Use the exact HTTPS create URL and independently verified 32-byte public key")
    return {"host": host, "public_key": public_key}


def updated(config, entry):
    if not isinstance(config, dict) or "pin" not in config:
        raise ValueError("Expected witness configuration")
    entries = config.get("registration_hosts", [])
    if not isinstance(entries, list) or len(entries) > 16:
        raise ValueError("Invalid existing registration hosts")
    checked = []
    for item in entries:
        if not isinstance(item, dict) or set(item) != {"host", "public_key"}:
            raise ValueError("Invalid existing registration host")
        checked.append(registration(**item))
    if len({item["host"] for item in checked}) != len(checked):
        raise ValueError("Duplicate existing hosting URL")
    matches = [item for item in checked if item["host"] == entry["host"]]
    if matches:
        if matches != [entry]:
            raise ValueError("Hosting key conflict; rotation requires a separate reviewed procedure")
        return config
    if len(checked) >= 16:
        raise ValueError("Registration host limit reached")
    return dict(config, registration_hosts=checked + [entry])


def require_stopped():
    running = subprocess.check_output([
        "docker", "ps", "-q", "--filter", "label=com.docker.compose.project=elo-witness",
        "--filter", "label=com.docker.compose.service=witness",
    ], text=True, timeout=15)
    if running.strip():
        raise ValueError("Stop witness and retain its independent checkpoint before changing trust")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--host", required=True, help="Exact URL from the independently verified registration-host.json")
    parser.add_argument("--public-key", required=True, help="Public registration key, not the hosting-profile key")
    args = parser.parse_args()
    if sys.platform != "linux" or os.geteuid() != 0:
        raise ValueError("Run as root on the witness Linux host")
    entry = registration(args.host, args.public_key)
    root = args.state
    if not root.is_absolute() or ".." in root.parts:
        raise ValueError("Use an absolute state path without parent components")
    for path in (root, *root.parents):
        if path.is_symlink():
            raise ValueError("Symlink state paths are forbidden")
    spec = importlib.util.spec_from_file_location("elo_provision", Path(__file__).with_name("init.py"))
    provision = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(provision)
    provision.metadata(root, 0, 0o700, directory=True)
    if provision.read(root / "role", 0) != b"witness\n":
        raise ValueError("This is not witness state")
    config_path = root / "witness/config/config.json"
    uid = provision.UIDS["witness"]
    provision.metadata(config_path.parent, uid, 0o700, directory=True)
    original = provision.read(config_path, uid)
    config = json.loads(original)
    next_config = updated(config, entry)
    if next_config == config:
        print("Registration key already pinned; no changes")
        return
    require_stopped()
    temporary = config_path.with_name(".registration-" + os.urandom(8).hex())
    try:
        provision.create(temporary, provision.json_bytes(next_config), uid)
        require_stopped()
        if provision.read(config_path, uid) != original:
            raise ValueError("Configuration changed concurrently")
        os.replace(temporary, config_path)
        fd = os.open(config_path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        temporary.unlink(missing_ok=True)
    print("Pinned registration key. State and journal preserved; witness remains stopped.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        raise SystemExit(str(error))
