#!/usr/bin/env python3
"""Sign a public hosting profile in an offline, unprivileged one-shot container."""

import argparse
import html
import json
import os
from pathlib import Path
import re
import subprocess
import sys

import importlib.util

spec = importlib.util.spec_from_file_location("container_init", Path(__file__).with_name("init.py"))
provision = importlib.util.module_from_spec(spec)
spec.loader.exec_module(provision)


def hosting_page(link):
    return """<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<meta name="referrer" content="no-referrer"><title>Add elo hosting</title>
<style>body{font:18px system-ui;max-width:40rem;margin:4rem auto;padding:1rem}button{display:inline-block;padding:1rem}textarea{width:100%;height:8rem}img{display:block;width:min(100%,24rem);height:auto;margin:2rem auto}</style>
<h1>Add elo hosting</h1><p>Verify this hosting profile with its operator before importing it into elo.</p>
<p>In elo, open Hosting and scan this QR code, or copy the link below and paste it into the hosting import field.</p>
<img src="hosting-qr.svg" alt="QR code for importing this elo hosting profile">
<label for="link">Hosting link</label><textarea id="link" readonly>LINK</textarea>
<button id="copy" type="button">Copy link</button><p id="copy-status" role="status"></p>
<script>document.getElementById('copy').addEventListener('click',async()=>{const field=document.getElementById('link');const status=document.getElementById('copy-status');try{await navigator.clipboard.writeText(field.value);status.textContent='Copied. Paste this link in elo Hosting.';}catch{field.focus();field.select();status.textContent='Select and copy the hosting link, then paste it in elo Hosting.';}});</script>
<p>This public link contains endpoints, capabilities and public keys. It does not grant permission to create or join a Space.</p></html>
""".replace("LINK", html.escape(link, quote=True)).encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    provision.require(sys.platform == "linux" and os.geteuid() == 0, "Run as root on the initialized API host.")
    provision.require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", args.version), "Invalid image version.")
    root = args.state.absolute()
    provision.metadata(root, 0, 0o700, directory=True)
    provision.require(provision.read(root / "role", 0) == b"api\n", "Only the API host signs hosting profiles.")
    source = root / "export/config"
    output = root / "export/data"
    provision.metadata(source, 21005, 0o700, directory=True)
    provision.metadata(output, 21005, 0o700, directory=True)
    destination = output / "hosting-profile.json"
    provision.require(not destination.exists() and not destination.is_symlink(),
                      "Export already exists; review the existing public profile instead of overwriting it.")
    subprocess.run([
        "docker", "run", "--rm", "--pull", "never", "--network", "none", "--read-only",
        "--user", "21005:21005", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
        "--pids-limit", "64", "--memory", "128m", "--memory-swap", "128m", "--ulimit", "core=0",
        "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=8m,mode=0700,uid=21005,gid=21005",
        "--mount", f"type=bind,src={source},dst=/input,readonly",
        "--mount", f"type=bind,src={output},dst=/output",
        "elo-api:" + args.version, "elo-team", "hosting-config",
        "--input", "/input/manifest-input.json", "--key", "/input/signing-key.bin",
        "--output", "/output/hosting-profile.json",
        "--qr-output", "/output/hosting-qr.svg",
    ], check=True)
    value = json.loads(provision.read(destination, 21005))
    provision.require(set(value) == {"record", "link"} and isinstance(value["record"], str)
                      and isinstance(value["link"], str) and value["link"].startswith("elo://hosting/v1#"),
                      "Unexpected hosting-config output.")
    link = value["link"]
    qr = provision.read(output / "hosting-qr.svg", 21005, maximum=1024 * 1024)
    provision.require(b"<svg" in qr and b"</svg>" in qr, "Missing local QR SVG output.")
    provision.stable(root / "public/hosting-profile.json", provision.json_bytes(value), 0, 0o644)
    provision.stable(root / "public/hosting-link.txt", (link + "\n").encode(), 0, 0o644)
    provision.stable(root / "public/hosting-qr.svg", qr, 0, 0o644)
    provision.stable(root / "public/hosting-profile.html", hosting_page(link), 0, 0o644)
    print("Public profile exported to " + str(root / "public") + ". The API proxy serves this directory at /hosting/ when started.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        sys.exit(str(error))
