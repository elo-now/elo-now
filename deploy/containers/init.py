#!/usr/bin/env python3
"""Provision one Linux container host without starting services or activating witness."""

import argparse
import ipaddress
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

UIDS = {"api": 21001, "witness": 21002, "storage": 21003, "proxy": 21004, "export": 21005,
        "wake": 21006, "calls": 21007, "media": 21008, "turn": 21009}
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


def managed_storage(value):
    require(isinstance(value, dict) and set(value) == {"provider", "allowed_owners"}, "Invalid managed storage configuration.")
    provider, owners = value["provider"], value["allowed_owners"]
    require(isinstance(provider, dict), "Invalid provider configuration.")
    require(isinstance(owners, list) and len(owners) <= 1024
            and all(isinstance(owner, str) and HEX.fullmatch(owner) for owner in owners)
            and len(set(owners)) == len(owners), "Invalid managed storage owner allowlist.")
    if provider.get("provider") == "mega_folder":
        require(set(provider) == {"provider", "folder_link", "write_auth"}
                and isinstance(provider["folder_link"], str)
                and re.fullmatch(r"https://mega\.nz/folder/[A-Za-z0-9_-]{8}#[A-Za-z0-9_-]{22,64}", provider["folder_link"])
                and isinstance(provider["write_auth"], str)
                and re.fullmatch(r"[A-Za-z0-9_-]{16,128}", provider["write_auth"]), "Invalid limited MEGA folder credentials.")
        return value
    require(set(provider) == {"provider", "endpoint", "region", "bucket", "access_key", "secret_key"}
            and provider["provider"] == "s3_compatible", "Unsupported managed storage provider.")
    require(all(isinstance(item, str) and 0 < len(item.encode()) <= 4096
                and not any(unicodedata.category(c) == "Cc" for c in item) for item in provider.values()),
            "Invalid S3 configuration value.")
    endpoint = urlsplit(provider["endpoint"])
    require(endpoint.scheme == "https" and endpoint.hostname and not endpoint.username and not endpoint.password
            and endpoint.path in {"", "/"} and not endpoint.query and not endpoint.fragment,
            "S3 requires an HTTPS origin without credentials, path or query.")
    require(re.fullmatch(r"[A-Za-z0-9-]{1,128}", provider["region"])
            and re.fullmatch(r"[A-Za-z0-9.-]+", provider["bucket"]), "Invalid S3 region or bucket.")
    return value


def firebase_account(value):
    require(isinstance(value, dict) and value.get("type") == "service_account"
            and value.get("token_uri") == "https://oauth2.googleapis.com/token"
            and isinstance(value.get("project_id"), str) and re.fullmatch(r"[a-z][a-z0-9-]{4,62}", value["project_id"])
            and isinstance(value.get("client_email"), str) and value["client_email"].endswith(".iam.gserviceaccount.com")
            and isinstance(value.get("private_key_id"), str) and 1 <= len(value["private_key_id"]) <= 256
            and isinstance(value.get("private_key"), str)
            and value["private_key"].startswith("-----BEGIN PRIVATE KEY-----\n")
            and value["private_key"].rstrip().endswith("-----END PRIVATE KEY-----"), "Invalid Firebase service account.")
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


def proxy_config(role, public_origin, storage, wake=False, calls=False):
    global_options = "{\n\tadmin off\n\tpersist_config off\n}\n"
    if role == "api":
        routes = ""
        if wake:
            routes += """\t@wake path /v1/routes /v1/routes/* /v1/wake /wake/v1/account-deletion /wake/health
\thandle @wake {
\t\trequest_body {
\t\t\tmax_size 1048576
\t\t}
\t\treverse_proxy 127.0.0.1:8788 {
\t\t\theader_up X-Real-IP {remote_host}
\t\t}
\t}
"""
        if calls:
            routes += """\t@calls path /calls/v1/connect /calls/v1/health
\thandle @calls {
\t\trequest_body {
\t\t\tmax_size 1048576
\t\t}
\t\treverse_proxy 127.0.0.1:18920 {
\t\t\theader_up X-Real-IP {remote_host}
\t\t}
\t}
\t@media_private path /media/twirp /media/twirp/*
\thandle @media_private {
\t\trespond 404
\t}
\thandle_path /media/* {
\t\treverse_proxy 127.0.0.1:7880
\t}
"""
        routes += """\tredir /hosting /hosting/ 308
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


def setup_calls(root, public_origin, public_ip, uids):
    """Share only the individual admission/media secrets needed by each service."""
    data = root / "calls/data"
    admission = secret(root / "calls/config/admission.key", uids["calls"], data, hexadecimal=True)
    stable(root / "api/config/call-admission.key", admission, uids["api"])
    media_secret = secret(root / "calls/config/media.key", uids["calls"], data, hexadecimal=True).decode()
    turn_secret = secret(root / "calls/config/turn.key", uids["calls"], data, hexadecimal=True).decode()
    domain = urlsplit(public_origin).hostname
    config = {"bind": "127.0.0.1:18920", "public_url": public_origin + "/calls/v1",
              "data": "/var/lib/elo-calls", "admission_url": "http://127.0.0.1:18901/internal/calls/admission",
              "admission_key": "/etc/elo/calls/admission.key", "max_connections": 128,
              "media": {"url": "wss://" + domain + "/media", "api_url": "http://127.0.0.1:7880",
                        "api_key": "elo-private", "api_secret": media_secret, "turn_secret": turn_secret,
                        "turn_urls": ["turn:" + domain + ":3478?transport=udp", "turn:" + domain + ":3478?transport=tcp"]}}
    stable(root / "calls/config/config.json", json_bytes(config), uids["calls"])
    # JSON is valid YAML, with no interpolated secrets or hostnames in shell code.
    media = {"port": 7880, "bind_addresses": ["127.0.0.1"], "keys": {"elo-private": media_secret},
             "rtc": {"tcp_port": 7881, "udp_port": 7882, "use_external_ip": False, "node_ip": public_ip,
                     "turn_servers": [{"host": domain, "port": 3478, "protocol": "udp", "secret": turn_secret},
                                      {"host": domain, "port": 3478, "protocol": "tcp", "secret": turn_secret}]},
             "room": {"max_participants": 32}, "logging": {"level": "warn"}}
    stable(root / "media/config/livekit.yaml", json_bytes(media), uids["media"])
    turn = f"""listening-port=3478
listening-ip={public_ip}
relay-ip={public_ip}
realm={domain}
server-name={domain}
use-auth-secret
static-auth-secret={turn_secret}
fingerprint
min-port=49160
max-port=49200
total-quota=256
user-quota=16
max-bps=2000000
bps-capacity=64000000
stale-nonce=600
no-tls
no-dtls
no-cli
no-multicast-peers
no-tcp-relay
no-software-attribute
no-rfc5780
no-stun-backward-compatibility
denied-peer-ip=0.0.0.0-0.255.255.255
denied-peer-ip=10.0.0.0-10.255.255.255
denied-peer-ip=100.64.0.0-100.127.255.255
denied-peer-ip=127.0.0.0-127.255.255.255
denied-peer-ip=169.254.0.0-169.254.255.255
denied-peer-ip=172.16.0.0-172.31.255.255
denied-peer-ip=192.168.0.0-192.168.255.255
denied-peer-ip=::1
denied-peer-ip=fc00::-fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
denied-peer-ip=fe80::-febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff
log-file=stdout
simple-log
pidfile=/tmp/turnserver.pid
"""
    stable(root / "turn/config/turnserver.conf", turn.encode(), uids["turn"])


def prepare(root, role, public_origin, version, witness_pin=None, storage=False, uids=None, owner=None,
            creators=(), name="Private elo", storage_url=None, managed=None, advertise_managed_s3=False,
            mega=False, advertise_managed=None, firebase=None, call_ip=None, public_hosting=False):
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
    require(not public_hosting or (role == "api" and not creators), "Public hosting is an API-only opt-in incompatible with creator allowlists.")
    require(not (advertise_managed_s3 and advertise_managed), "Choose one managed storage advertisement.")
    advertise_managed = "s3" if advertise_managed_s3 else advertise_managed
    require(not (public_hosting and advertise_managed), "Public hosting requires each Space owner's own storage credentials.")
    require(advertise_managed in {None, "s3", "mega"}, "Invalid managed storage advertisement.")
    require(not advertise_managed or (role == "api" and storage_url is not None), "Advertising managed storage requires an API broker URL.")
    require(not mega or (role == "witness" and storage), "MEGA belongs on the witness host with storage enabled.")
    if managed is not None:
        require(role == "witness" and storage, "Managed credentials belong only on the witness host with storage enabled.")
        managed_storage(managed)
        require(managed["provider"]["provider"] != "mega_folder" or mega, "Managed MEGA requires --with-mega.")
    if firebase is not None:
        require(role == "api", "Firebase credentials belong only on the API host.")
        firebase_account(firebase)
    if call_ip is not None:
        require(role == "api" and isinstance(call_ip, str), "Calls belong on the API host.")
        address = ipaddress.ip_address(call_ip)
        require(address.version == 4 and address.is_global, "Calls require the API host's public IPv4 address.")
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
    roles += (["wake"] if firebase is not None else []) + (["calls", "media", "turn"] if call_ip else [])
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
        retentions = [21600, 43200, 86400] if public_hosting else [86400, 172800, "no_expiry"]
        config = {"root": "/var/lib/elo-api", "public_url": public_origin, "max_spaces_per_identity": 2,
                  "max_spaces": 128, "max_space_creations_per_day": 32, "mailbox_quota_bytes": 150000000,
                  "backup_access_key": "/etc/elo/api/backup-access.key", "witness": witness_pin,
                  "allowed_creators": None if public_hosting else list(creators), "allowed_message_retentions": retentions}
        if call_ip:
            config["call_admission_key"] = "/etc/elo/api/call-admission.key"
            setup_calls(root, public_origin, call_ip, uids)
        if firebase is not None:
            stable(root / "wake/config/firebase.json", json_bytes(firebase), uids["wake"])
            stable(root / "wake/config/config.json", json_bytes({"public_url": public_origin}), uids["wake"])
        signing_key = secret(root / "export/config/signing-key.bin", uids["export"], root / "api/data")
        body = {"v": 1, "kind": "hosting.configuration", "revision": 1, "name": name,
                "signing_public_key": public_key(signing_key), "create_url": public_origin + "/spaces/v1/create",
                "witness": witness_pin, "storage": {"url": storage_url, "managed":
                    {"provider": advertise_managed, "retention_hours": 1} if advertise_managed else None} if storage_url else None,
                "push_url": public_origin + "/" if firebase is not None else None,
                "call_url": public_origin + "/calls/v1" if call_ip else None,
                "message_lifetimes": retentions, "default_message_lifetime": 86400}
        stable(root / "export/config/manifest-input.json", json_bytes(body), uids["export"])
    stable(service / "config/config.json", json_bytes(config), uids[role])
    if storage:
        service = root / "storage"
        secret(service / "config/secret.key", uids["storage"], service / "data")
        config = {"bind": "127.0.0.1:17846", "public_url": public_origin + "/storage/v1",
                  "data": "/var/lib/elo-storage", "secret_key": "/etc/elo/storage/secret.key",
                  "max_spaces": 128, "trusted_loopback_proxy": True, "witness": witness_pin}
        if managed is not None:
            stable(service / "config/managed-storage.json", json_bytes(managed), uids["storage"])
            config["managed_storage"] = "/etc/elo/storage/managed-storage.json"
        stable(service / "config/config.json", json_bytes(config), uids["storage"])
    stable(root / "public/witness-pin.json", json_bytes(witness_pin), owner, 0o644)
    stable(root / "proxy/config/Caddyfile", proxy_config(role, public_origin, storage, firebase is not None, bool(call_ip)), uids["proxy"])
    env = f"ELO_STATE={root}\nELO_VERSION={version}\n"
    profiles = []
    if storage:
        profiles.append("storage")
        env += "ELO_STORAGE_IMAGE=elo-storage" + ("-mega" if mega else "") + "\n"
    if firebase is not None:
        profiles.append("wake")
    if call_ip:
        profiles.append("calls")
    if profiles:
        env += "COMPOSE_PROFILES=" + ",".join(profiles) + "\n"
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
    parser.add_argument("--with-mega", action="store_true", help="Witness: select the broker image with the limited MEGA folder adapter.")
    parser.add_argument("--managed-storage", type=Path, help="Witness: root-owned mode-0600 managed MEGA or S3 JSON.")
    parser.add_argument("--advertise-managed", choices=("s3", "mega"), help="API: advertise an independently configured managed provider.")
    parser.add_argument("--firebase", type=Path, help="API: root-owned mode-0600 Firebase service account for this app's project.")
    parser.add_argument("--call-ip", help="API: public IPv4 of this host; enables call control, LiveKit and TURN.")
    parser.add_argument("--public-hosting", action="store_true", help="API: explicitly allow public creation with 6/12/24-hour retention and owner-supplied storage.")
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
    require(not (args.managed_s3 and args.managed_storage), "Choose one managed storage input file.")
    managed_file = args.managed_storage or args.managed_s3
    managed = json.loads(read(managed_file, 0)) if managed_file else None
    if args.managed_s3:
        require(managed.get("provider", {}).get("provider") == "s3_compatible", "--managed-s3 requires an S3 provider.")
    firebase = json.loads(read(args.firebase, 0)) if args.firebase else None
    result = prepare(args.state, args.role, args.origin, args.version, supplied_pin, args.with_storage,
                     creators=args.creator, name=args.name, storage_url=args.storage_url, managed=managed,
                     advertise_managed_s3=args.advertise_managed_s3, mega=args.with_mega,
                     advertise_managed=args.advertise_managed, firebase=firebase, call_ip=args.call_ip,
                     public_hosting=args.public_hosting)
    print(json.dumps({"state": str(args.state), "role": args.role, "witness": result,
                      "services_started": False, "witness_activated": False}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        sys.exit(str(error))
