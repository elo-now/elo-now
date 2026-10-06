#!/usr/bin/env python3
"""Validate public desktop release settings before installing or compiling dependencies."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
from urllib.parse import urlsplit


def https_address(value: str, path: str, name: str) -> str:
    try:
        url = urlsplit(value)
        host = url.hostname or ""
        try:
            ipaddress.ip_address(host)
            valid_host = True
        except ValueError:
            valid_host = len(host) <= 253 and all(
                re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", label)
                for label in host.rstrip(".").split(".")
            )
        valid = (
            value.isascii() and not any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value)
            and url.scheme == "https" and valid_host and url.username is None and url.password is None
            and "?" not in value and "#" not in value and (url.path or "/") == path
            and (url.port is None or 1 <= url.port <= 65535) and "\\" not in value
        )
    except ValueError:
        valid = False
    if not valid:
        raise ValueError(f"{name} must be an HTTPS URL with path {path}, without credentials, query or fragment")
    return value


def prepare(settings: dict[str, str], source: dict, runner_os: str) -> tuple[dict, dict]:
    def get(name: str) -> str:
        return settings.get(f"RELEASE_{name}", "")

    version, build = get("VERSION"), get("BUILD_NUMBER")
    if bool(version) != bool(build):
        raise ValueError("Version and build number overrides must be supplied together")
    version = version or source["version"]
    build = build or source["bundle"]["macOS"]["bundleVersion"]
    if not re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", version):
        raise ValueError("Version must use the release format major.minor.patch")
    if any(int(component) > 65535 for component in version.split(".")):
        raise ValueError("Version components exceed desktop installer limits")
    if not re.fullmatch(r"[1-9][0-9]{0,9}", build) or int(build) > 2_147_483_647:
        raise ValueError("Build number must be a positive integer no greater than 2147483647")

    env = {}
    api = get("API_URL")
    if api:
        # API origin and legacy host/wake overrides are mutually exclusive in Rust.
        env["TAURI_ELO_API_URL"] = https_address(api, "/", "API origin")
    else:
        # Preserve the existing publisher's explicit endpoint configuration.
        env["TAURI_ELO_SPACE_HOST_URL"] = https_address(get("SPACE_HOST_URL"), "/spaces/v1/create", "Hosting URL")
        env["TAURI_ELO_WAKE_URL"] = https_address(get("WAKE_URL"), "/", "Wake URL")

    witness = [get("WITNESS_URL"), get("WITNESS_PUBLIC_KEY"), get("WITNESS_KEY_GENERATION")]
    if any(witness):
        url, key, generation = witness
        if not all(witness):
            raise ValueError("Witness URL, public key and generation must be supplied together")
        if not re.fullmatch(r"[0-9a-f]{64}", key):
            raise ValueError("Witness public key must contain exactly 64 lowercase hexadecimal characters")
        if not re.fullmatch(r"[1-9][0-9]{0,15}", generation) or int(generation) > 2**53 - 1:
            raise ValueError("Witness generation must be an integer from 1 to 9007199254740991")
        env["TAURI_ELO_WITNESS_URL"] = https_address(url, "/witness/v1", "Witness URL")
        env["TAURI_ELO_WITNESS_PUBLIC_KEY"] = key
        env["TAURI_ELO_WITNESS_KEY_GENERATION"] = generation
    if get("STORAGE_URL"):
        env["TAURI_ELO_STORAGE_URL"] = https_address(get("STORAGE_URL"), "/storage/v1", "Storage URL")

    config = {"version": version, "bundle": {"macOS": {"bundleVersion": build}}}
    if runner_os == "macOS":
        config["bundle"]["macOS"]["signingIdentity"] = "-"
    return config, env


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source = json.loads(Path("apps/desktop/src-tauri/tauri.conf.json").read_text())
    config, env = prepare(dict(os.environ), source, os.environ["RUNNER_OS"])
    args.output.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    metadata = {"version": config["version"], "build": config["bundle"]["macOS"]["bundleVersion"],
                "commit": os.environ.get("GITHUB_SHA"), "public_configuration": env}
    args.output.with_name("desktop-release-metadata.json").write_text(
        json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    # Unconfigured optional settings must be absent, not empty, for build.rs.
    env["ELO_DESKTOP_CONFIG"] = args.output.resolve().as_posix()
    env["ELO_DESKTOP_VERSION"] = config["version"]
    with open(os.environ["GITHUB_ENV"], "a", encoding="utf-8", newline="\n") as stream:
        for name, value in env.items():
            stream.write(f"{name}={value}\n")


if __name__ == "__main__":
    main()
