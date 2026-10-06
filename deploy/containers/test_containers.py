#!/usr/bin/env python3
"""Local, daemon-free tests for provisioning and deployment boundaries."""

import copy
import importlib.util
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + ".py"))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


provision, activation, source_bundle, locked = (load(name) for name in ("init", "activate", "bundle", "verify_lock"))
profile_export = load("export")
runtime_smoke = load("smoke")


class ProvisioningTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve() / "state"
        self.owner = (os.getuid(), os.getgid())
        self.uids = {name: self.owner for name in provision.UIDS}

    def prepare(self, role="witness", **kwargs):
        return provision.prepare(self.root, role, "https://" + role + ".example.test", "1.0.5-test",
                                 owner=self.owner, uids=self.uids, **kwargs)

    def test_witness_and_storage_keys_are_stable_and_independent(self):
        pin = self.prepare(storage=True)
        key = (self.root / "witness/config/signing-key.bin").read_bytes()
        storage = (self.root / "storage/config/secret.key").read_bytes()
        self.assertEqual(len(key), 32)
        self.assertNotEqual(key, storage)
        self.assertEqual(self.prepare(storage=True), pin)
        self.assertEqual((self.root / "witness/config/signing-key.bin").read_bytes(), key)
        self.assertEqual(pin["public_key"], provision.public_key(key))
        self.assertFalse(any(self.root.rglob("activation.json")))
        self.assertFalse(any(self.root.rglob("startup.json")))

    def test_existing_data_survives_reinitialization(self):
        self.prepare()
        sentinel = self.root / "witness/data/journal.sqlite"
        sentinel.write_bytes(b"existing database and receipts")
        self.prepare()
        self.assertEqual(sentinel.read_bytes(), b"existing database and receipts")

    def test_missing_key_with_existing_data_fails_closed(self):
        self.prepare()
        key = self.root / "witness/config/signing-key.bin"
        key.unlink()
        (self.root / "witness/data/journal.sqlite").write_bytes(b"data")
        with self.assertRaisesRegex(ValueError, "Missing key"):
            self.prepare()
        self.assertFalse(key.exists())

    def test_unsafe_permissions_symlink_and_hardlink_are_rejected(self):
        self.prepare()
        key = self.root / "witness/config/signing-key.bin"
        original = key.read_bytes()
        key.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "permissions"):
            self.prepare()
        key.chmod(0o600)
        second = key.with_name("linked-key")
        os.link(key, second)
        with self.assertRaisesRegex(ValueError, "Hard-linked"):
            self.prepare()
        second.unlink()
        key.rename(second)
        key.symlink_to(second)
        with self.assertRaisesRegex(ValueError, "file type"):
            self.prepare()
        self.assertEqual(second.read_bytes(), original)

    def test_conflicting_configuration_is_not_overwritten(self):
        self.prepare()
        before = (self.root / "witness/config/config.json").read_bytes()
        with self.assertRaisesRegex(ValueError, "differs"):
            provision.prepare(self.root, "witness", "https://other.example.test", "1.0.5-test",
                              owner=self.owner, uids=self.uids)
        self.assertEqual((self.root / "witness/config/config.json").read_bytes(), before)

    def test_invalid_origins_fail_before_creating_state(self):
        for value in ("http://host.test", "https://user@host.test", "https://host.test/", "https://host.test?q=x",
                      "https://host.test\n", "https://host.test:443", "https://127.0.0.1", "https://-host.test"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                provision.prepare(self.root, "witness", value, "test", owner=self.owner, uids=self.uids)
            self.assertFalse(self.root.exists())

    def test_api_defaults_to_no_creators_and_has_separate_export_key(self):
        pin = {"url": "https://witness.example.test/witness/v1", "public_key": "a" * 64, "key_generation": 1}
        self.prepare(role="api", witness_pin=pin, storage_url="https://witness.example.test/storage/v1")
        config = json.loads((self.root / "api/config/config.json").read_text())
        body = json.loads((self.root / "export/config/manifest-input.json").read_text())
        self.assertEqual(config["allowed_creators"], [])
        self.assertEqual(config["allowed_message_retentions"], [86400, 172800, "no_expiry"])
        self.assertEqual(config["witness"], pin)
        backup = (self.root / "api/config/backup-access.key").read_bytes()
        signer = (self.root / "export/config/signing-key.bin").read_bytes()
        self.assertEqual(len(backup), 64)
        self.assertNotEqual(bytes.fromhex(backup.decode()), signer)
        self.assertEqual(body["signing_public_key"], provision.public_key(signer))
        self.assertEqual(body["storage"]["url"], "https://witness.example.test/storage/v1")
        self.assertEqual(body["name"], "Private elo")

    def test_managed_s3_credentials_stay_on_the_storage_service(self):
        managed = {"provider": {"provider": "s3_compatible", "endpoint": "https://s3.example.test",
                               "region": "test-region", "bucket": "test-bucket",
                               "access_key": "fictional-access", "secret_key": "fictional-private-value"},
                   "allowed_owners": ["a" * 64]}
        self.prepare(storage=True, managed=managed)
        path = self.root / "storage/config/managed-storage.json"
        self.assertEqual(json.loads(path.read_text()), managed)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        config = json.loads((self.root / "storage/config/config.json").read_text())
        self.assertEqual(config["managed_storage"], "/etc/elo/storage/managed-storage.json")
        for other in (self.root / "public").rglob("*"):
            if other.is_file():
                self.assertNotIn(b"fictional-private-value", other.read_bytes())
        self.assertNotIn("managed", json.loads((self.root / "witness/config/config.json").read_text()))
        with self.assertRaises(ValueError):
            provision.managed_storage(dict(managed, allowed_owners=["not-an-identity"]))
        with self.assertRaises(ValueError):
            provision.managed_storage(dict(managed, provider=dict(managed["provider"], provider="mega_folder")))

    def test_advertised_managed_option_contains_no_provider_secrets(self):
        pin = {"url": "https://witness.example.test/witness/v1", "public_key": "a" * 64, "key_generation": 1}
        self.prepare(role="api", witness_pin=pin, storage_url="https://witness.example.test/storage/v1",
                     advertise_managed_s3=True, creators=["c" * 64])
        body = json.loads((self.root / "export/config/manifest-input.json").read_text())
        self.assertEqual(body["storage"]["managed"], {"provider": "s3", "retention_hours": 1})
        config = json.loads((self.root / "api/config/config.json").read_text())
        self.assertEqual(config["allowed_creators"], ["c" * 64])
        self.assertNotIn("managed_storage", config)

    def test_managed_mega_requires_adapter_and_credentials_remain_role_local(self):
        managed = {"provider": {"provider": "mega_folder", "folder_link": "https://mega.nz/folder/abcdefgh#" + "a" * 22,
                               "write_auth": "b" * 32}, "allowed_owners": ["c" * 64]}
        with self.assertRaisesRegex(ValueError, "--with-mega"):
            self.prepare(storage=True, managed=managed)
        self.assertFalse(self.root.exists())
        self.prepare(storage=True, mega=True, managed=managed)
        self.assertIn("ELO_STORAGE_IMAGE=elo-storage-mega", (self.root / "compose.env").read_text())
        for path in self.root.rglob("*"):
            if path.is_file() and path != self.root / "storage/config/managed-storage.json":
                self.assertNotIn(managed["provider"]["write_auth"].encode(), path.read_bytes())

    def test_push_and_calls_have_distinct_secrets_and_signed_endpoint_advertisements(self):
        pin = {"url": "https://witness.example.test/witness/v1", "public_key": "a" * 64, "key_generation": 1}
        firebase = {"type": "service_account", "project_id": "test-elo", "client_email": "test@test-elo.iam.gserviceaccount.com",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "private_key_id": "fictional-key", "private_key": "-----BEGIN PRIVATE KEY-----\nsynthetic\n-----END PRIVATE KEY-----\n"}
        self.prepare(role="api", witness_pin=pin, firebase=firebase, call_ip="8.8.8.8")
        body = json.loads((self.root / "export/config/manifest-input.json").read_text())
        self.assertEqual(body["push_url"], "https://api.example.test/")
        self.assertEqual(body["call_url"], "https://api.example.test/calls/v1")
        secrets = [(self.root / f"calls/config/{name}.key").read_bytes() for name in ("admission", "media", "turn")]
        self.assertEqual(len(set(secrets)), 3)
        self.assertEqual((self.root / "api/config/call-admission.key").read_bytes(), secrets[0])
        call = json.loads((self.root / "calls/config/config.json").read_text())
        self.assertEqual(call["admission_url"], "http://127.0.0.1:18901/internal/calls/admission")
        media = json.loads((self.root / "media/config/livekit.yaml").read_text())
        self.assertEqual(media["keys"]["elo-private"], secrets[1].decode())
        self.assertEqual(media["rtc"]["turn_servers"][0]["secret"], secrets[2].decode())
        self.assertIn(secrets[2].decode(), (self.root / "turn/config/turnserver.conf").read_text())
        public = json.dumps(body)
        for secret in secrets:
            self.assertNotIn(secret.decode(), public)
        self.assertNotIn("PRIVATE KEY", public)
        self.prepare(role="api", witness_pin=pin, firebase=firebase, call_ip="8.8.8.8")
        self.assertEqual(secrets[0], (self.root / "calls/config/admission.key").read_bytes())

    def test_private_service_inputs_fail_before_creating_state(self):
        pin = {"url": "https://witness.example.test/witness/v1", "public_key": "a" * 64, "key_generation": 1}
        for bad in ({"call_ip": "127.0.0.1"}, {"call_ip": "10.0.0.1"}, {"firebase": {"type": "service_account"}},
                    {"advertise_managed": "mega"}, {"mega": True}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self.prepare(role="api", witness_pin=pin, **bad)
            self.assertFalse(self.root.exists())

    def test_public_hosting_requires_explicit_opt_in_and_retains_public_limits(self):
        pin = {"url": "https://witness.example.test/witness/v1", "public_key": "a" * 64, "key_generation": 1}
        for bad in ({"creators": ["a" * 64]}, {"advertise_managed": "mega", "storage_url": "https://witness.example.test/storage/v1"}):
            with self.assertRaises(ValueError):
                self.prepare(role="api", witness_pin=pin, public_hosting=True, **bad)
            self.assertFalse(self.root.exists())
        self.prepare(role="api", witness_pin=pin, public_hosting=True)
        config = json.loads((self.root / "api/config/config.json").read_text())
        body = json.loads((self.root / "export/config/manifest-input.json").read_text())
        self.assertIsNone(config["allowed_creators"])
        self.assertEqual(config["allowed_message_retentions"], [21600, 43200, 86400])
        self.assertEqual(body["message_lifetimes"], [21600, 43200, 86400])
        self.assertEqual(body["default_message_lifetime"], 86400)


class ActivationTests(unittest.TestCase):
    def setUp(self):
        self.anchor = {"expected_position": {"sequence": 25, "record_id": "b" * 64},
                       "public_key": "a" * 64, "key_generation": 1}
        self.startup = {"startup_nonce": "c" * 64, "observed_position": copy.deepcopy(self.anchor["expected_position"]),
                        "public_key": "a" * 64, "key_generation": 1}

    def test_exact_external_anchor_and_current_nonce(self):
        result = activation.activation(self.startup, self.anchor, now_ms=1000)
        self.assertEqual(result["expected_position"], self.anchor["expected_position"])
        self.assertEqual(result["startup_nonce"], self.startup["startup_nonce"])
        self.assertEqual(result["expires_at_ms"], 301000)

    def test_rollback_wrong_key_and_self_observation_are_rejected(self):
        for field, value in (("public_key", "d" * 64), ("key_generation", 2),
                             ("expected_position", {"sequence": 24, "record_id": "b" * 64})):
            bad = dict(self.anchor, **{field: value})
            with self.subTest(field=field), self.assertRaises(ValueError):
                activation.activation(self.startup, bad)
        with self.assertRaises(ValueError):
            activation.activation(self.startup, self.startup)

    def test_empty_journal_requires_explicit_first_bootstrap(self):
        self.anchor["expected_position"] = self.startup["observed_position"] = {"sequence": 0, "record_id": None}
        with self.assertRaises(ValueError):
            activation.activation(self.startup, self.anchor)
        activation.activation(self.startup, self.anchor, first_bootstrap=True)
        self.startup["observed_position"] = {"sequence": 1, "record_id": "d" * 64}
        with self.assertRaises(ValueError):
            activation.activation(self.startup, self.anchor, first_bootstrap=True)

    def test_activation_is_private_and_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory)
            document = activation.activation(self.startup, self.anchor)
            activation.install(document, runtime)
            path = runtime / "activation.json"
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(path.stat().st_nlink, 1)
            self.assertEqual(json.loads(path.read_text()), document)
            with self.assertRaises(ValueError):
                activation.install(document, runtime)


class SourceAndComposeTests(unittest.TestCase):
    def test_smoke_cleanup_continues_after_failure_and_reports_unremoved_resources(self):
        smoke = runtime_smoke.Smoke("synthetic-test")
        smoke.containers = ["owned-first", "owned-second"]
        smoke.volumes = ["owned-volume"]
        smoke.network = "owned-network"
        responses = [subprocess.TimeoutExpired("docker", 15),
                     subprocess.CompletedProcess([], 1, "", "No such container: owned-first"),
                     subprocess.CompletedProcess([], 1, "", "volume is in use"),
                     subprocess.CompletedProcess([], 0, "", "")]
        with mock.patch.object(runtime_smoke, "run", side_effect=responses) as command:
            errors = smoke.cleanup()
        self.assertEqual(command.call_count, 4)
        self.assertEqual(len(errors), 2)
        self.assertTrue(any("owned-second" in error for error in errors))
        self.assertTrue(any("owned-volume" in error for error in errors))

    def test_public_page_has_local_qr_and_copy_instructions_without_a_deep_link_cta(self):
        class Elements(HTMLParser):
            def __init__(self):
                super().__init__()
                self.elements = []
            def handle_starttag(self, tag, attrs):
                self.elements.append((tag, dict(attrs)))
        link = "elo://hosting/v1#synthetic-public-link"
        page = profile_export.hosting_page(link).decode()
        parser = Elements()
        parser.feed(page)
        self.assertTrue(any(tag == "img" and attrs.get("src") == "hosting-qr.svg" for tag, attrs in parser.elements))
        self.assertFalse(any(attrs.get("href", "").startswith("elo:") for _, attrs in parser.elements))
        self.assertIn("scan this QR code", page)
        self.assertIn("paste it into the hosting import field", page)
        self.assertIn("navigator.clipboard.writeText", page)
        self.assertNotIn("Open in elo", page)
        self.assertIn(link, page)
        self.assertFalse(any(attrs.get("src", "").startswith(("https:", "http:")) for _, attrs in parser.elements))

    def test_api_proxy_serves_public_profile_before_backend_fallback(self):
        config = provision.proxy_config("api", "https://api.example.test", False).decode()
        self.assertIn("redir /hosting /hosting/ 308", config)
        self.assertIn("handle_path /hosting/*", config)
        self.assertIn("root * /srv/elo-public", config)
        self.assertIn("index hosting-profile.html", config)
        self.assertIn("handle {", config)
        self.assertIn("reverse_proxy 127.0.0.1:18900", config)
        self.assertNotIn("18901", config)
        self.assertNotIn("/export", config)
        self.assertNotIn("/hosting/", provision.proxy_config("witness", "https://witness.example.test", True).decode())

    def test_optional_proxy_routes_are_explicit_and_media_admin_stays_private(self):
        minimal = provision.proxy_config("api", "https://api.example.test", False).decode()
        full = provision.proxy_config("api", "https://api.example.test", False, True, True).decode()
        for path in ("/v1/routes/*", "/v1/wake", "/wake/v1/account-deletion", "/calls/v1/connect", "/calls/v1/state", "/media/*"):
            self.assertNotIn(path, minimal)
            self.assertIn(path, full)
        self.assertIn("@media_private path /media/twirp /media/twirp/*", full)
        self.assertIn("handle @media_private {\n\t\trespond 404\n\t}", full)
        self.assertNotIn("18901", full)
        self.assertIn("@calls path /calls/v1/connect /calls/v1/state /calls/v1/health\n", full)
        self.assertNotIn("/calls/*", full)
        self.assertNotIn("/calls/v1/*", full)
        self.assertNotIn("/internal/calls", full)

    def test_nginx_call_state_route_is_exact_and_bounded(self):
        config = (HERE.parent / "self-host/nginx.conf.example").read_text()
        route = config.split("location = /calls/v1/state {", 1)[1].split("}", 1)[0]
        self.assertIn("proxy_pass http://127.0.0.1:18920;", route)
        self.assertIn("client_max_body_size 1m;", route)
        self.assertIn("limit_req zone=elo_call_connect", route)
        self.assertIn("access_log off;", route)
        self.assertNotIn("location /calls", config)
        self.assertNotIn("location ^~ /calls", config)
        self.assertNotIn("location /internal/calls", config)

    def test_lock_normalization_cannot_change_dependency_versions_or_checksums(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            entries = "\n".join(f'[[package]]\nname = "{name}"\nversion = "1.0.5"\n'
                                for name in source_bundle.SERVERS)
            entries += '[[package]]\nname = "sample-dependency"\nversion = "1.2.3"\nchecksum = "reviewed"\n'
            (root / "before").write_text(entries)
            (root / "after").write_text(entries)
            locked.verify(root / "before", root / "after")
            for original, replacement in (("1.2.3", "1.2.4"), ("reviewed", "changed")):
                (root / "after").write_text(entries.replace(original, replacement))
                with self.assertRaises(ValueError):
                    locked.verify(root / "before", root / "after")

    def test_source_context_excludes_private_client_and_runtime_trees(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "context"
            source_bundle.bundle(HERE.parents[1], output)
            paths = [str(path.relative_to(output)) for path in output.rglob("*")]
            self.assertTrue((output / "crates/elo-team/src/main.rs").exists())
            self.assertTrue((output / "migrations/001_replica.sql").exists())
            for forbidden in (".private", "MEMORY.md", "vendor/", "docs/", "target/", "credentials", ".git/"):
                self.assertFalse(any(forbidden in path for path in paths), forbidden)
            self.assertEqual([str(path.relative_to(output)) for path in (output / "apps").rglob("*") if path.is_file()],
                             ["apps/desktop/src/locales/native.en.json"])
            with self.assertRaises(ValueError):
                source_bundle.bundle(HERE.parents[1], output)
        self.assertEqual((HERE / ".dockerignore").read_bytes(), (HERE / "Dockerfile.dockerignore").read_bytes())

    @unittest.skipUnless(shutil.which("docker"), "Docker Compose CLI is not installed")
    def test_compose_configuration_and_service_boundaries(self):
        environment = dict(os.environ, ELO_STATE="/srv/elo-test", ELO_VERSION="1.0.5-test")
        for role in ("api", "witness"):
            result = subprocess.run(["docker", "compose", "-f", str(HERE / f"compose.{role}.yaml"),
                                     "--profile", "*", "config", "--format", "json"],
                                    env=environment, capture_output=True, text=True, check=True, timeout=30)
            config = json.loads(result.stdout)
            for name, service in config["services"].items():
                self.assertEqual(service["network_mode"], "host")
                self.assertTrue(service["read_only"])
                self.assertNotIn("ports", service)
                self.assertNotIn("privileged", service)
                self.assertNotIn("build", service)
                self.assertIn("ALL", service["cap_drop"])
                self.assertFalse(service["user"].startswith("0:"))
                for mount in service["volumes"]:
                    self.assertNotIn("docker.sock", mount["source"])
                    self.assertNotIn("/export", mount["source"])
                    if "/config" in mount["source"]:
                        self.assertTrue(mount["read_only"])
                    if mount["source"].endswith("/public"):
                        self.assertEqual((role, name, mount["target"]), ("api", "proxy", "/srv/elo-public"))
                        self.assertTrue(mount["read_only"])
                    self.assertFalse(mount["bind"].get("create_host_path", False))
                if name == "witness":
                    self.assertIn("/livez", " ".join(service["healthcheck"]["test"]))
                    self.assertNotIn("activate", " ".join(service["healthcheck"]["test"]))
                    self.assertTrue(any("/run/elo-witness" in value for value in service["tmpfs"]))
            if role == "api":
                self.assertTrue(any(mount["target"] == "/srv/elo-public" for mount in config["services"]["proxy"]["volumes"]))


if __name__ == "__main__":
    unittest.main()
