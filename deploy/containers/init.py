#!/usr/bin/env python3
"""Provision one Linux container host without starting services or activating witness."""

import argparse
import json
import os
from pathlib import Path
import re
import resource
import stat
import subprocess
import sys
import unicodedata
from urllib.parse import urlsplit

UIDS = {"api": 21001, "witness": 21002, "storage": 21003, "proxy": 21004, "export": 21005}
HEX = re.compile(r"[0-9a-f]{64}\Z")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def origin(value):
    require(isinstance(value, str) and re.fullmatch(r"https://[a-z0-9.-]+", value) is not None,
            "Use a lowercase HTTPS DNS origin, without a port, slash, path or credentials.")
    parsed = urlsplit(value)
    labels = (parsed.hostname or "").split(".")
    require(len(labels) >= 2 and all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                                   for label in labels), "Invalid DNS hostname.")
    require(not all(label.isdigit() for label in labels), "Use a public DNS name for automatic TLS.")
    return value


def pin(value):
    require(isinstance(value, dict) and set(value) == {"url", "public_key", "key_generation"},
            "Expected only url, public_key and key_generation in the witness pin.")
    require(isinstance(value["url"], str) and value["url"].endswith("/witness/v1"), "Invalid witness URL.")
    origin(value["url"][:-len("/witness/v1")])
    require(isinstance(value["public_key"], str) and HEX.fullmatch(value["public_key"]), "Invalid witness public key.")
    require(type(value["key_generation"]) is int and 0 < value["key_generation"] <= 2**53 - 1,
            "Invalid witness key generation.")
    return value


def identity(uid):
    return (uid, uid) if isinstance(uid, int) else uid


def metadata(path, uid, mode, directory=False):
    info = path.lstat()
    require((stat.S_ISDIR if directory else stat.S_ISREG)(info.st_mode), f"Unexpected file type: {path}")
    require(directory or info.st_nlink == 1, f"Hard-linked file rejected: {path}")
    require((info.st_uid, info.st_gid) == identity(uid), f"Wrong owner: {path}")
    require(stat.S_IMODE(info.st_mode) == mode, f"Wrong permissions: {path}")


def directory(path, uid, mode=0o700):
    try:
        path.mkdir(mode=mode)
    except FileExistsError:
        pass
    else:
        os.chown(path, *identity(uid))
        os.chmod(path, mode)
    metadata(path, uid, mode, directory=True)


def create(path, data, uid, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.fchown(fd, *identity(uid))
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def read(path, uid, mode=0o600, maximum=65536):
    metadata(path, uid, mode)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        result = stream.read(maximum + 1)
    require(len(result) <= maximum, f"Oversized file: {path}")
    return result


def stable(path, data, uid, mode=0o600):
    if not path.exists() and not path.is_symlink():
        create(path, data, uid, mode)
    require(read(path, uid, mode, maximum=max(65536, len(data))) == data, f"Existing file differs; refusing to overwrite: {path}")


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def managed_s3(value):
    require(isinstance(value, dict) and set(value) == {"provider", "allowed_owners"}, "Invalid managed S3 configuration.")
    provider, owners = value["provider"], value["allowed_owners"]
    require(isinstance(provider, dict) and set(provider) ==
            {"provider", "endpoint", "region", "bucket", "access_key", "secret_key"}
            and provider["provider"] == "s3_compatible", "Only the S3-compatible provider is packaged.")
    require(all(isinstance(item, str) and 0 < len(item.encode()) <= 4096
                and not any(unicodedata.category(c) == "Cc" for c in item) for item in provider.values()),
            "Invalid S3 configuration value.")
    endpoint = urlsplit(provider["endpoint"])
    require(endpoint.scheme == "https" and endpoint.hostname and not endpoint.username and not endpoint.password
            and endpoint.path in {"", "/"} and not endpoint.query and not endpoint.fragment,
            "S3 requires an HTTPS origin without credentials, path or query.")
    require(re.fullmatch(r"[A-Za-z0-9-]{1,128}", provider["region"])
            and re.fullmatch(r"[A-Za-z0-9.-]+", provider["bucket"]), "Invalid S3 region or bucket.")
    require(isinstance(owners, list) and len(owners) <= 1024
            and all(isinstance(owner, str) and HEX.fullmatch(owner) for owner in owners)
            and len(set(owners)) == len(owners), "Invalid managed S3 owner allowlist.")
    return value


def secret(path, uid, data_directory, hexadecimal=False):
    if not path.exists() and not path.is_symlink():
        require(not any(data_directory.iterdir()), f"Missing key with existing data; restore the original key: {path}")
        value = os.urandom(32)
        create(path, value.hex().encode() if hexadecimal else value, uid)
    value = read(path, uid, maximum=64)
    require(bool(HEX.fullmatch(value.decode("ascii", errors="replace"))) if hexadecimal else len(value) == 32,
            f"Invalid private key length or encoding: {path}")
    return value


def public_key(seed):
    result = subprocess.run(["openssl", "pkey", "-inform", "DER", "-pubout", "-outform", "DER"],
                            input=bytes.fromhex("302e020100300506032b657004220420") + seed,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10, check=True)
    prefix = bytes.fromhex("302a300506032b6570032100")
    require(result.stdout.startswith(prefix) and len(result.stdout) == len(prefix) + 32,
            "OpenSSL could not derive an Ed25519 public key.")
    return result.stdout[len(prefix):].hex()


def proxy_config(role, public_origin, storage):
    global_options = "{\n\tadmin off\n\tpersist_config off\n}\n"
    if role == "api":
        routes = """\tredir /hosting /hosting/ 308
\thandle_path /hosting/* {
\t\troot * /srv/elo-public
\t\theader Cache-Control no-store
\t\tfile_server {
\t\t\tindex hosting-profile.html
\t\t}
\t}
\thandle {
\t\trequest_body {
\t\t\tmax_size 18874368
\t\t}
\t\treverse_proxy 127.0.0.1:18900 {
\t\t\theader_up X-Real-IP {remote_host}
\t\t\ttransport http {
\t\t\t\tdial_timeout 5s
\t\t\t\tresponse_header_timeout 65s
\t\t\t}
\t\t}
\t}
"""
    else:
        routes = """\t@witness path /witness/v1/command /witness/v1/head\n\thandle @witness {\n\t\trequest_body {\n\t\t\tmax_size 9437184\n\t\t}\n\t\treverse_proxy 127.0.0.1:17845 {\n\t\t\theader_up X-Real-IP {remote_host}\n\t\t\ttransport http {\n\t\t\t\tdial_timeout 5s\n\t\t\t\tresponse_header_timeout 65s\n\t\t\t}\n\t\t}\n\t}\n"""
        if storage:
            routes += """\t@storage path /storage/v1/command /storage/v1/objects/*\n\thandle @storage {\n\t\trequest_body {\n\t\t\tmax_size 18874368\n\t\t}\n\t\treverse_proxy 127.0.0.1:17846 {\n\t\t\theader_up X-Real-IP {remote_host}\n\t\t\ttransport http {\n\t\t\t\tdial_timeout 5s\n\t\t\t\tresponse_header_timeout 95s\n\t\t\t}\n\t\t}\n\t}\n"""
        routes += "\thandle {\n\t\trespond 404\n\t}\n"
    return (global_options + public_origin + " {\n" + routes + "}\n").encode()


def prepare(root, role, public_origin, version, witness_pin=None, storage=False, uids=None, owner=None,
            creators=(), name="Private elo", storage_url=None, managed=None, advertise_managed_s3=False):
    uids = UIDS if uids is None else uids
    owner = os.getuid() if owner is None else owner
    origin(public_origin)
    require(role in {"api", "witness"}, "Unknown role.")
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", version), "Invalid image version.")
    require(role == "witness" or not storage, "Storage belongs on the witness host.")
    require(all(isinstance(value, str) and HEX.fullmatch(value) for value in creators), "Invalid creator identity ID.")
    require(len(set(creators)) == len(creators), "Duplicate creator identity ID.")
    require(isinstance(name, str) and 1 <= len(name.encode()) <= 96 and name.strip() == name
            and not any(unicodedata.category(c) in {"Cc", "Cf"} for c in name), "Invalid hosting name.")
    require(role == "api" or not creators, "Creator allowlists belong on the API host.")
    require(not advertise_managed_s3 or (role == "api" and storage_url is not None), "Advertising managed S3 requires an API broker URL.")
    if managed is not None:
        require(role == "witness" and storage, "Managed S3 credentials belong only on the witness host with storage enabled.")
        managed_s3(managed)
    if storage_url is not None:
        require(role == "api" and storage_url.endswith("/storage/v1"), "Invalid broker URL.")
        origin(storage_url[:-len("/storage/v1")])
    if role == "api":
        pin(witness_pin)
        require(witness_pin["url"] != public_origin + "/witness/v1", "Use an independent witness origin and host.")
        if storage_url:
            require(storage_url[:-len("/storage/v1")] == witness_pin["url"][:-len("/witness/v1")],
                    "This two-host package places storage on the witness origin.")
    # Environment files and Compose bind paths must not contain interpolation or YAML characters.
    require(root.is_absolute() and re.fullmatch(r"/[A-Za-z0-9_./-]+", str(root)), "Use a simple absolute state path.")
    require(".." not in root.parts, "Parent path components are forbidden.")
    for parent in root.parents:
        require(not parent.is_symlink(), f"Symlink parent rejected: {parent}")
    require(root.parent.is_dir(), "Create the parent directory first.")
    public_key(bytes(32))  # Validate OpenSSL support before creating any state.
    directory(root, owner)
    stable(root / "role", (role + "\n").encode(), owner)
    directory(root / "public", owner, 0o755)
    roles = [role, "proxy"] + (["storage"] if storage else []) + (["export"] if role == "api" else [])
    for role_name in roles:
        directory(root / role_name, owner)
        for subdirectory in ("config", "data"):
            directory(root / role_name / subdirectory, uids[role_name])
    service = root / role
    if role == "witness":
        key = secret(service / "config/signing-key.bin", uids[role], service / "data")
        witness_pin = {"url": public_origin + "/witness/v1", "public_key": public_key(key), "key_generation": 1}
        config = {"bind": "127.0.0.1:17845", "pin": witness_pin, "data": "/var/lib/elo-witness",
                  "signing_key": "/etc/elo/witness/signing-key.bin", "startup_file": "/run/elo-witness/startup.json",
                  "activation_file": "/run/elo-witness/activation.json", "trusted_loopback_proxy": True}
    else:
        secret(service / "config/backup-access.key", uids[role], service / "data", hexadecimal=True)
        config = {"root": "/var/lib/elo-api", "public_url": public_origin, "max_spaces_per_identity": 2,
                  "max_spaces": 128, "max_space_creations_per_day": 32, "mailbox_quota_bytes": 150000000,
                  "backup_access_key": "/etc/elo/api/backup-access.key", "witness": witness_pin,
                  "allowed_creators": list(creators), "allowed_message_retentions": [86400, 172800, "no_expiry"]}
        signing_key = secret(root / "export/config/signing-key.bin", uids["export"], root / "api/data")
        body = {"v": 1, "kind": "hosting.configuration", "revision": 1, "name": name,
                "signing_public_key": public_key(signing_key), "create_url": public_origin + "/spaces/v1/create",
                "witness": witness_pin, "storage": {"url": storage_url, "managed":
                    {"provider": "s3", "retention_hours": 1} if advertise_managed_s3 else None} if storage_url else None,
                "push_url": None, "message_lifetimes": [86400, 172800, "no_expiry"], "default_message_lifetime": 86400}
        stable(root / "export/config/manifest-input.json", json_bytes(body), uids["export"])
    stable(service / "config/config.json", json_bytes(config), uids[role])
    if storage:
        service = root / "storage"
        secret(service / "config/secret.key", uids["storage"], service / "data")
        config = {"bind": "127.0.0.1:17846", "public_url": public_origin + "/storage/v1",
                  "data": "/var/lib/elo-storage", "secret_key": "/etc/elo/storage/secret.key",
                  "max_spaces": 128, "trusted_loopback_proxy": True, "witness": witness_pin}
        if managed is not None:
            stable(service / "config/managed-s3.json", json_bytes(managed), uids["storage"])
            config["managed_storage"] = "/etc/elo/storage/managed-s3.json"
        stable(service / "config/config.json", json_bytes(config), uids["storage"])
    stable(root / "public/witness-pin.json", json_bytes(witness_pin), owner, 0o644)
    stable(root / "proxy/config/Caddyfile", proxy_config(role, public_origin, storage), uids["proxy"])
    env = f"ELO_STATE={root}\nELO_VERSION={version}\n"
    if storage:
        env += "COMPOSE_PROFILES=storage\n"
    stable(root / "compose.env", env.encode(), owner)
    return witness_pin


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("role", choices=("api", "witness"))
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--origin", required=True)
    parser.add_argument("--version", required=True, help="Local image tag, e.g. 1.0.5-source-REVISION")
    parser.add_argument("--witness-pin", type=Path)
    parser.add_argument("--with-storage", action="store_true")
    parser.add_argument("--creator", action="append", default=[], help="API: identity allowed to create Spaces; repeat as needed.")
    parser.add_argument("--name", default="Private elo", help="Public hosting profile display name.")
    parser.add_argument("--storage-url", help="API: independently operated broker URL ending in /storage/v1.")
    parser.add_argument("--managed-s3", type=Path, help="Witness: root-owned mode-0600 private managed S3 JSON.")
    parser.add_argument("--advertise-managed-s3", action="store_true", help="API: advertise the separately configured managed S3 option.")
    args = parser.parse_args()
    require(sys.platform == "linux" and os.geteuid() == 0, "Run this initializer as root on the target Linux host.")
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    require((args.role == "api") == (args.witness_pin is not None), "Only API initialization requires --witness-pin.")
    for parent in args.state.absolute().parents:
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not stat.S_IMODE(info.st_mode) & 0o022,
                "State ancestors must be root-owned directories without group/world write permission.")
    supplied_pin = json.loads(args.witness_pin.read_text()) if args.witness_pin else None
    managed = json.loads(read(args.managed_s3, 0)) if args.managed_s3 else None
    result = prepare(args.state, args.role, args.origin, args.version, supplied_pin, args.with_storage,
                     creators=args.creator, name=args.name, storage_url=args.storage_url, managed=managed,
                     advertise_managed_s3=args.advertise_managed_s3)
    print(json.dumps({"state": str(args.state), "role": args.role, "witness": result,
                      "services_started": False, "witness_activated": False}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        sys.exit(str(error))
