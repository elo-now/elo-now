#!/usr/bin/env python3
"""Prepare an isolated, removable API test instance beside the public container host.

This provisions files only: it does not start containers, change firewall rules,
restart witness, or alter the public host. Start the generated Compose project
explicitly after reviewing it. The default creator allowlist is empty.

After testing, stop only the elo-api-test Compose project, remove its dedicated
9443 firewall rule and administration units, then remove only its own state.
Keep the public API, shared witness/storage, media/TURN, certificates and SFTP.
"""

import argparse
import copy
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from urllib.parse import urlsplit

PROJECT = "elo-api-test"
PORTS = {"https": 9443, "api": 19900, "control": 19901, "wake": 8878, "calls": 19920}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def source_module(bundle):
    spec = importlib.util.spec_from_file_location("elo_test_host_provision", bundle / "init.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def safe_path(path):
    require(path.is_absolute() and re.fullmatch(r"/[A-Za-z0-9_./-]+", str(path))
            and ".." not in path.parts, "Use a simple absolute path without parent components.")
    for part in (path, *path.parents):
        require(not part.is_symlink(), "Symlink paths are not allowed.")
    return path


def test_origin(public_origin):
    parsed = urlsplit(public_origin)
    require(parsed.scheme == "https" and parsed.hostname and parsed.netloc == parsed.hostname
            and not parsed.path and not parsed.query and not parsed.fragment,
            "The source must use its existing HTTPS hostname on port 443.")
    return public_origin + ":9443"


def media_configuration(value, public_origin):
    require(isinstance(value, dict) and set(value) == {"url", "api_url", "api_key", "api_secret", "turn_secret", "turn_urls"},
            "Unexpected shared media configuration.")
    hostname = urlsplit(public_origin).hostname
    require(value["url"] == "wss://" + hostname + "/media"
            and value["api_url"] == "http://127.0.0.1:7880"
            and isinstance(value["api_key"], str) and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value["api_key"])
            and all(isinstance(value[key], str) and re.fullmatch(r"[0-9a-f]{64}", value[key]) for key in ("api_secret", "turn_secret"))
            and value["turn_urls"] == ["turn:" + hostname + ":3478?transport=udp", "turn:" + hostname + ":3478?transport=tcp"],
            "Shared media must retain the public host's existing endpoints and credentials.")
    return copy.deepcopy(value)


def proxy_configuration(origin, hostname):
    return f"""{{
    admin off
    persist_config off
    auto_https off
    servers {{
        protocols h1 h2
    }}
}}
{origin} {{
    tls /etc/caddy/public-tls/{hostname}.crt /etc/caddy/public-tls/{hostname}.key
    @wake path /v1/routes /v1/routes/* /v1/wake /wake/v1/account-deletion /wake/health
    handle @wake {{
        request_body {{
            max_size 1048576
        }}
        reverse_proxy 127.0.0.1:{PORTS['wake']} {{
            header_up X-Real-IP {{remote_host}}
        }}
    }}
    @calls path /calls/v1/connect /calls/v1/state /calls/v1/health
    handle @calls {{
        request_body {{
            max_size 1048576
        }}
        reverse_proxy 127.0.0.1:{PORTS['calls']} {{
            header_up X-Real-IP {{remote_host}}
        }}
    }}
    @shared_media path /media /media/*
    handle @shared_media {{
        respond 404
    }}
    redir /hosting /hosting/ 308
    handle_path /hosting/* {{
        root * /srv/elo-public
        header Cache-Control no-store
        file_server {{
            index hosting-profile.html
        }}
    }}
    handle {{
        request_body {{
            max_size 18874368
        }}
        reverse_proxy 127.0.0.1:{PORTS['api']} {{
            header_up X-Real-IP {{remote_host}}
            transport http {{
                dial_timeout 5s
                response_header_timeout 65s
            }}
        }}
    }}
}}
""".encode()


def mount(source, target, readonly=False):
    result = {"type": "bind", "source": str(source), "target": target, "bind": {"create_host_path": False}}
    if readonly:
        result["read_only"] = True
    return result


def compose_configuration(root, certificate_directory, origin, version, uids):
    services = {}
    for role, image, target in (("api", "elo-api", "api"), ("wake", "elo-wake", "wake"), ("calls", "elo-calls", "calls")):
        uid = uids[role]
        memory = "2g" if role == "api" else "512m"
        services[role] = {
            "image": f"{image}:{version}", "pull_policy": "never", "user": f"{uid}:{uid}",
            "network_mode": "host", "read_only": True, "init": True, "restart": "unless-stopped",
            "stop_signal": "SIGINT", "stop_grace_period": "45s", "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges:true"], "pids_limit": 512,
            "mem_limit": memory, "memswap_limit": memory, "ulimits": {"core": 0, "nofile": 8192},
            "tmpfs": [f"/tmp:rw,noexec,nosuid,nodev,size=32m,mode=0700,uid={uid},gid={uid}"],
            "volumes": [mount(root / role / "config", f"/etc/elo/{target}", True),
                        mount(root / role / "data", f"/var/lib/elo-{target}")],
            "healthcheck": {"test": ["CMD", "curl", "--fail", "--silent", "--max-time", "3",
                                      f"http://127.0.0.1:{PORTS[role]}/" + {"api": "spaces/v1/health", "wake": "wake/health", "calls": "calls/v1/health"}[role]],
                            "interval": "30s", "timeout": "5s", "retries": 3},
            "logging": {"driver": "json-file", "options": {"max-size": "10m", "max-file": "3"}},
        }
    services["api"]["command"] = ["elo-team", "host", "--config", "/etc/elo/api/config.json", "--bind", "127.0.0.1:19900"]
    services["wake"]["command"] = ["python3", "/opt/elo/wake.py", "--listen", "127.0.0.1:8878"]
    services["calls"]["command"] = ["elo-call-service", "--config", "/etc/elo/calls/config.json"]
    uid = uids["proxy"]
    services["proxy"] = {
        "image": "caddy:2.11.7-alpine", "pull_policy": "never", "user": f"{uid}:{uid}",
        "network_mode": "host", "read_only": True, "restart": "unless-stopped",
        # The image's Caddy binary carries this file capability even on a high port.
        "cap_drop": ["ALL"], "cap_add": ["NET_BIND_SERVICE"], "security_opt": ["no-new-privileges:true"],
        "pids_limit": 128, "mem_limit": "256m", "memswap_limit": "256m", "ulimits": {"core": 0},
        "environment": {"XDG_DATA_HOME": "/tmp/caddy-data", "XDG_CONFIG_HOME": "/tmp/caddy-config"},
        "tmpfs": [f"/tmp:rw,noexec,nosuid,nodev,size=16m,mode=0700,uid={uid},gid={uid}"],
        "volumes": [mount(root / "proxy/config", "/etc/caddy", True),
                    mount(certificate_directory, "/etc/caddy/public-tls", True),
                    mount(root / "public", "/srv/elo-public", True)],
        "logging": {"driver": "json-file", "options": {"max-size": "10m", "max-file": "3"}},
    }
    return {"name": PROJECT, "services": services}


def prepare(root, source, bundle, version):
    for path in (root, source, bundle):
        safe_path(path)
    require(root.name == PROJECT and root != source and source not in root.parents and root not in source.parents,
            "Use a separate elo-api-test state directory outside the public API state.")
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", version), "Invalid image version.")
    require(root.parent.is_dir(), "Create the state parent directory first.")
    parent_info = root.parent.lstat()
    require(parent_info.st_uid == 0 and not parent_info.st_mode & 0o022,
            "The test state parent directory must be root-owned and not writable by others.")
    for code in (bundle / "init.py", bundle / "export.py"):
        info = code.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == 0 and not info.st_mode & 0o022,
                "Container tools must be regular root-owned files, not writable by others.")
    provision = source_module(bundle)
    uids = provision.UIDS
    provision.metadata(source, 0, 0o700, directory=True)
    require(provision.read(source / "role", 0) == b"api\n", "Source is not the public API state.")
    api = json.loads(provision.read(source / "api/config/config.json", uids["api"]))
    previous_manifest = json.loads(provision.read(source / "export/config/manifest-input.json", uids["export"]))
    public_origin = provision.origin(api["public_url"])
    origin = test_origin(public_origin)
    hostname = urlsplit(public_origin).hostname
    witness = provision.pin(api["witness"])
    require(previous_manifest.get("witness") == witness, "The public API witness configuration is inconsistent.")
    storage = previous_manifest.get("storage")
    require(isinstance(storage, dict) and storage.get("url") == witness["url"][:-len("/witness/v1")] + "/storage/v1",
            "The existing independent storage broker is required.")
    existing_calls = json.loads(provision.read(source / "calls/config/config.json", uids["calls"]))
    media = media_configuration(existing_calls.get("media"), public_origin)
    firebase = provision.firebase_account(json.loads(provision.read(source / "wake/config/firebase.json", uids["wake"])))
    certificate_directory = source / "proxy/data/caddy/certificates/acme-v02.api.letsencrypt.org-directory" / hostname
    safe_path(certificate_directory)
    require(certificate_directory.is_dir(), "The existing public TLS certificate directory is missing.")
    for extension in ("crt", "key"):
        path = certificate_directory / (hostname + "." + extension)
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == uids["proxy"]
                and not info.st_mode & (0o077 if extension == "key" else 0o022),
                "The public TLS certificate and key must be private regular files owned by Caddy.")
    subprocess.run(["openssl", "x509", "-in", str(certificate_directory / (hostname + ".crt")),
                    "-checkhost", hostname, "-checkend", "3600", "-noout"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=10)

    # No source files are written. All new credentials and databases belong to the test instance.
    provision.directory(root, 0)
    provision.stable(root / "role", b"api\n", 0)
    provision.directory(root / "public", 0, 0o755)
    for role in ("api", "wake", "calls", "proxy", "export"):
        provision.directory(root / role, 0)
        for directory in ("config", "data"):
            provision.directory(root / role / directory, uids[role])
    # The read-only certificate submount needs an existing mount point beneath /etc/caddy.
    provision.directory(root / "proxy/config/public-tls", uids["proxy"])
    provision.secret(root / "api/config/backup-access.key", uids["api"], root / "api/data", hexadecimal=True)
    admission = provision.secret(root / "calls/config/admission.key", uids["calls"], root / "calls/data", hexadecimal=True)
    provision.stable(root / "api/config/call-admission.key", admission, uids["api"])
    signing_key = provision.secret(root / "export/config/signing-key.bin", uids["export"], root / "api/data")
    retentions = [86400, 172800, "no_expiry"]
    api_config = {"root": "/var/lib/elo-api", "public_url": origin, "max_spaces_per_identity": 2,
                  "max_spaces": 32, "max_space_creations_per_day": 16, "mailbox_quota_bytes": 150000000,
                  "backup_access_key": "/etc/elo/api/backup-access.key", "witness": witness,
                  "allowed_creators": [], "allowed_message_retentions": retentions,
                  "call_admission_key": "/etc/elo/api/call-admission.key"}
    manifest = {"v": 1, "kind": "hosting.configuration", "revision": 1, "name": "9bits test",
                "signing_public_key": provision.public_key(signing_key), "create_url": origin + "/spaces/v1/create",
                "witness": witness, "storage": {"url": storage["url"], "managed": None},
                "push_url": origin + "/", "call_url": origin + "/calls/v1",
                "message_lifetimes": retentions, "default_message_lifetime": 86400}
    calls_config = {"bind": "127.0.0.1:19920", "public_url": origin + "/calls/v1",
                    "data": "/var/lib/elo-calls", "admission_url": "http://127.0.0.1:19901/internal/calls/admission",
                    "admission_key": "/etc/elo/calls/admission.key", "max_connections": 64, "media": media}
    for path, content, uid in (
        (root / "api/config/config.json", api_config, uids["api"]),
        (root / "export/config/manifest-input.json", manifest, uids["export"]),
        (root / "wake/config/firebase.json", firebase, uids["wake"]),
        (root / "wake/config/config.json", {"public_url": origin}, uids["wake"]),
        (root / "calls/config/config.json", calls_config, uids["calls"]),
    ):
        provision.stable(path, provision.json_bytes(content), uid)
    provision.stable(root / "public/witness-pin.json", provision.json_bytes(witness), 0, 0o644)
    provision.stable(root / "proxy/config/Caddyfile", proxy_configuration(origin, hostname), uids["proxy"])
    provision.stable(root / "compose.api.yaml", provision.json_bytes(compose_configuration(root, certificate_directory, origin, version, uids)), 0)
    provision.stable(root / "compose.env", f"ELO_STATE={root}\nELO_VERSION={version}\n".encode(), 0)
    for name in ("init.py", "export.py"):
        provision.stable(root / name, (bundle / name).read_bytes(), 0)
    provision.stable(root / "test-instance.json", provision.json_bytes({
        "v": 1, "project": PROJECT, "origin": origin, "ports": PORTS,
        "source_state": str(source), "shared_witness": witness["url"], "shared_storage": storage["url"],
        "shared_media": media["url"], "certificate_directory": str(certificate_directory),
        "initial_creator_policy": "deny_all_until_admin_allowlist_is_configured",
    }), 0)
    return origin


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-state", type=Path, default=Path("/srv/elo-api"))
    parser.add_argument("--state", type=Path, default=Path("/srv/elo-api-test"))
    parser.add_argument("--container-bundle", type=Path, required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    require(sys.platform == "linux" and os.geteuid() == 0, "Run as root on the existing API host.")
    os.umask(0o077)
    origin = prepare(args.state, args.source_state, args.container_bundle, args.version)
    print("Prepared isolated test hosting at " + origin + "; no services or firewall rules were changed.")
    print("Export the signed profile with the copied export.py, then start only the generated elo-api-test Compose project.")
    print("Space creation remains disabled until the administration panel has an explicit creator allowlist.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError, KeyError, TypeError) as error:
        sys.exit("Test hosting provisioning failed: " + str(error))
