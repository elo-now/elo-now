#!/usr/bin/env python3
"""Run the ignored S3 integration test with a disposable real RustFS server.

Linux x86_64 only; requires Python 3, OpenSSL, Cargo and about 1 GiB free disk.
Downloads the pinned official binary, verifies its published SHA-256, and binds
only to loopback using a private, ephemeral TLS CA. No cloud account is used.
The production adapter's public-address restriction is unchanged.

Source and checksum: https://github.com/rustfs/rustfs/releases/tag/1.0.0-rc.6
TLS layout: https://docs.rustfs.com/en/integration/tls-configured
Usage: python3 crates/elo-storage/tests/run_live_s3.py
"""

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import secrets
import shutil
import signal
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import zipfile


VERSION = "1.0.0-rc.6"
ASSET = f"rustfs-linux-x86_64-gnu-v{VERSION}.zip"
URL = f"https://github.com/rustfs/rustfs/releases/download/{VERSION}/{ASSET}"
SHA256 = "68d0df70b4c7b377e1bb9a2681b7325ffd00d6a78e3acb61e65d30d257459ae9"
TEST = "engine::tests::real_s3_sigv4_provider_rotation_and_signed_retention_lifecycle"


def private_write(path, value):
    with open(path, "x", encoding="utf-8") as output:
        os.chmod(path, 0o600)
        output.write(value)


def download_binary(root):
    archive = root / ASSET
    digest = hashlib.sha256()
    size = 0
    with urllib.request.urlopen(URL, timeout=30) as response, archive.open("xb") as output:
        if not response.url.startswith("https://"):
            raise RuntimeError("The release download did not use HTTPS")
        while chunk := response.read(1024 * 1024):
            size += len(chunk)
            if size > 160 * 1024 * 1024:
                raise RuntimeError("The release archive exceeds the download limit")
            digest.update(chunk)
            output.write(chunk)
    if digest.hexdigest() != SHA256:
        raise RuntimeError("The release checksum does not match the official pinned digest")
    binary = root / "rustfs"
    with zipfile.ZipFile(archive) as source:
        members = [m for m in source.infolist() if Path(m.filename).name == "rustfs" and not m.is_dir()]
        if len(members) != 1 or members[0].file_size > 600 * 1024 * 1024:
            raise RuntimeError("Unexpected release archive layout")
        # Extract only the executable to a fixed path; do not trust archive paths.
        with source.open(members[0]) as data, binary.open("xb") as output:
            shutil.copyfileobj(data, output)
    binary.chmod(0o700)
    archive.unlink()
    print(f"Verified official RustFS {VERSION} archive SHA-256", flush=True)
    return binary


def make_tls(root):
    tls = root / "tls"
    tls.mkdir(mode=0o700)
    ca = tls / "ca.pem"
    leaf = tls / "leaf.pem"
    extensions = tls / "extensions.cnf"
    private_write(extensions, "subjectAltName=IP:127.0.0.1\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n")
    commands = [
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=elo isolated S3 test CA", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-keyout", str(tls / "ca.key"), "-out", str(ca)],
        ["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=127.0.0.1", "-keyout", str(tls / "rustfs_key.pem"), "-out", str(tls / "leaf.csr")],
        ["openssl", "x509", "-req", "-in", str(tls / "leaf.csr"), "-CA", str(ca), "-CAkey", str(tls / "ca.key"), "-CAcreateserial", "-days", "1", "-extfile", str(extensions), "-out", str(leaf)],
    ]
    for command in commands:
        subprocess.run(command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
    private_write(tls / "rustfs_cert.pem", leaf.read_text() + ca.read_text())
    return tls, ca


def child_limits(parent_pid):
    # Stop the isolated provider if the supervisor is unexpectedly killed.
    if ctypes.CDLL(None).prctl(1, signal.SIGKILL, 0, 0, 0) != 0:
        os._exit(126)
    if os.getppid() != parent_pid:
        os._exit(126)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (256 * 1024 * 1024, 256 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_NOFILE, (1024, 1024))


def stop(process):
    if process is not None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pass
        # The direct child may have exited while a descendant still runs.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=10)


def run(repo, cargo):
    os.umask(0o077)
    if platform.system() != "Linux" or platform.machine() not in ("x86_64", "amd64"):
        raise RuntimeError("This pinned fixture supports Linux x86_64 only")
    if shutil.disk_usage(tempfile.gettempdir()).free < 1024 * 1024 * 1024:
        raise RuntimeError("The isolated fixture needs 1 GiB of free temporary disk")
    with tempfile.TemporaryDirectory(prefix="elo-live-s3-") as directory:
        root = Path(directory)
        provider = None
        tests = None
        access = "elo-test-" + secrets.token_hex(8)
        secret = secrets.token_hex(32)
        log = root / "provider.log"
        try:
            binary = download_binary(root)
            version = subprocess.run([str(binary), "--version"], check=True, capture_output=True, text=True, timeout=10)
            print(version.stdout.strip(), flush=True)
            tls, ca = make_tls(root)
            data = root / "data"
            data.mkdir(mode=0o700)
            private_write(root / "access", access)
            private_write(root / "secret", secret)
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                port = listener.getsockname()[1]
            endpoint = f"https://127.0.0.1:{port}"
            env = {k: v for k, v in os.environ.items() if not k.startswith("RUSTFS_")}
            env.update({
                "RUSTFS_ADDRESS": f"127.0.0.1:{port}",
                "RUSTFS_CONSOLE_ADDRESS": "127.0.0.1:0",
                "RUSTFS_CONSOLE_ENABLE": "false",
                "RUSTFS_ACCESS_KEY_FILE": str(root / "access"),
                "RUSTFS_SECRET_KEY_FILE": str(root / "secret"),
                "RUSTFS_TLS_PATH": str(tls),
                "RUSTFS_REGION": "us-east-1",
                "RUSTFS_OBS_ENDPOINT": "http://127.0.0.1:1",
                "RUST_LOG": "info",
            })
            with log.open("xb") as output:
                parent_pid = os.getpid()
                provider = subprocess.Popen([str(binary), "server", str(data)], cwd=root, env=env, stdout=output, stderr=subprocess.STDOUT, start_new_session=True, preexec_fn=lambda: child_limits(parent_pid))
            context = ssl.create_default_context(cafile=str(ca))
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
            deadline = time.monotonic() + 60
            while True:
                if provider.poll() is not None:
                    raise RuntimeError("The isolated S3 provider exited during startup")
                try:
                    with opener.open(endpoint + "/", timeout=2):
                        break
                except urllib.error.HTTPError:
                    break  # Authentication denial still verifies TLS and readiness.
                except (urllib.error.URLError, TimeoutError) as error:
                    if time.monotonic() > deadline:
                        raise RuntimeError(f"The isolated S3 provider did not become ready: {error}") from None
                    time.sleep(0.2)
            config = root / "fixture.json"
            private_write(config, json.dumps({"endpoint": endpoint, "root_pem": str(ca), "access_key": access, "secret_key": secret}))
            test_env = os.environ.copy()
            test_env.update({"ELO_S3_TEST_CONFIG": str(config), "CARGO_BUILD_JOBS": "2", "CARGO_PROFILE_DEV_DEBUG": "0", "CARGO_PROFILE_TEST_DEBUG": "0", "CARGO_INCREMENTAL": "0"})
            print("Running real S3 signature, ciphertext, retention and provider rotation checks", flush=True)
            command = [cargo, "test", "-p", "elo-storage", "--lib", "--locked", TEST, "--", "--exact", "--ignored", "--nocapture"]
            tests = subprocess.Popen(command, cwd=repo, env=test_env, start_new_session=True)
            status = tests.wait(timeout=300)
            if status:
                raise subprocess.CalledProcessError(status, command)
            print("Real S3 lifecycle passed; both test buckets were deleted", flush=True)
        except Exception:
            if log.exists():
                with log.open("rb") as output:
                    output.seek(max(0, log.stat().st_size - 6000))
                    tail = output.read().decode(errors="replace")
                print(tail.replace(access, "[test-access]").replace(secret, "[test-secret]"), flush=True)
            raise
        finally:
            stop(tests)
            stop(provider)
    print("Isolated S3 process, credentials, TLS keys and data removed", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[3])
    parser.add_argument("--cargo", default=shutil.which("cargo") or str(Path.home() / ".cargo/bin/cargo"))
    args = parser.parse_args()

    def interrupted(signum, frame):
        raise RuntimeError(f"S3 fixture interrupted by signal {signum}")

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGALRM):
        signal.signal(sig, interrupted)
    signal.alarm(420)
    run(args.repo.resolve(), args.cargo)
