"""Local-only admin boundary tests; no services, provider accounts or VPS access."""
from concurrent.futures import ThreadPoolExecutor
import http.client
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))
import schema
import server


def api_configuration():
    return {"name": "Example hosting", "message_lifetimes": [86400, 172800, "no_expiry"],
            "default_message_lifetime": 86400, "creation_mode": "allowlist", "allowed_creators": [], "managed_provider": None}


class SchemaTests(unittest.TestCase):
    def test_api_policy_bounds_and_strict_fields(self):
        self.assertEqual(schema.validate_configuration("api", api_configuration()), api_configuration())
        for update in [
            {"name": "x" * 97}, {"name": "hidden\u200btext"}, {"name": "wrong\nname"}, {"name": " "},
            {"message_lifetimes": [True]}, {"message_lifetimes": [86400, 86400]},
            {"message_lifetimes": [3600]}, {"default_message_lifetime": 43200},
            {"allowed_creators": ["a" * 64, "a" * 64]}, {"allowed_creators": ["A" * 64]},
            {"creation_mode": "public", "allowed_creators": ["a" * 64]},
            {"creation_mode": "public", "managed_provider": "mega"}, {"unknown": "hidden"},
        ]:
            with self.subTest(update=update), self.assertRaises(schema.ValidationError):
                schema.validate_configuration("api", api_configuration() | update)
        self.assertEqual(schema.validate_configuration("api", api_configuration() | {"creation_mode": "public"})["allowed_creators"], [])

    def test_witness_credentials_are_complete_or_omitted(self):
        mega = {"provider": "mega", "allowed_owners": ["a" * 64],
                "folder_link": "https://mega.nz/folder/abcdefgh#" + "x" * 22, "write_auth": "y" * 32}
        self.assertEqual(schema.validate_configuration("witness", mega), mega)
        self.assertEqual(schema.validate_configuration("witness", mega | {"folder_link": "", "write_auth": ""}),
                         {"provider": "mega", "allowed_owners": ["a" * 64]})
        for update in [{"write_auth": ""}, {"write_auth": "SECRET; command"}, {"provider": None}, {"folder_link": "http://mega.nz/folder/abcdefgh#" + "x" * 22}, {"s3_secret_key": "hidden"}]:
            with self.subTest(update=update), self.assertRaises(schema.ValidationError) as error:
                schema.validate_configuration("witness", mega | update)
            self.assertNotIn("SECRET", str(error.exception))
        s3 = {"provider": "s3", "allowed_owners": [], "s3_endpoint": "https://objects.example/", "s3_region": "eu-1", "s3_bucket": "bucket", "s3_access_key": "", "s3_secret_key": ""}
        normalized = schema.validate_configuration("witness", s3)
        self.assertNotIn("s3_secret_key", normalized)
        self.assertEqual(normalized["s3_endpoint"], "https://objects.example")
        for endpoint in ["http://objects.example", "https://user:SECRET@objects.example", "https://objects.example/path", "https://objects.example?key=SECRET", "https://objects.example#SECRET"]:
            with self.subTest(endpoint=endpoint), self.assertRaises(schema.ValidationError):
                schema.validate_configuration("witness", s3 | {"s3_endpoint": endpoint})

    def test_state_projection_never_returns_provider_secrets(self):
        public = schema.public_configuration("witness", {"provider": "mega", "configured": True,
            "allowed_owners": [], "folder_link": "SECRET", "write_auth": "SECRET", "password": "SECRET"})
        self.assertEqual(public, {"provider": "mega", "configured": True, "allowed_owners": []})
        public = schema.public_configuration("witness", {"provider": "s3", "configured": True,
            "allowed_owners": [], "public_fields": {"s3_endpoint": "https://objects.example", "s3_region": "eu-1", "s3_bucket": "bucket", "s3_secret_key": "SECRET"}})
        self.assertNotIn("SECRET", json.dumps(public))

    def test_origins_are_canonical_and_never_include_credentials(self):
        self.assertEqual(schema.origin("https://OBJECTS.example:443/"), "https://objects.example")
        for value in ["https://objects.example?", "https://objects.example#", "https://obje\u0107ts.example", "https://objects.example:invalid"]:
            with self.subTest(value=value), self.assertRaises(schema.ValidationError):
                schema.origin(value)


class HTTPTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for name in ("queue", "status", "static"):
            (self.root / name).mkdir(mode=0o700)
        for name in ("index.html", "style.css", "app.js", "en.json"):
            (self.root / "static" / name).write_text("{}")
        self.config = {"role": "api", "public_origin": "https://admin.example", "proxy_key": "p" * 64,
                       "related_admin_url": "https://witness.example/admin/"}
        self.saved = {"configuration": api_configuration() | {"storage_available": True, "private_key": "NEVER-RETURN-SECRET"},
                      "hosting": {"link": "elo://hosting/v1#signed", "qr_url": "/hosting/qr.svg", "revision": 1}, "secret": "NEVER-RETURN-SECRET"}
        self.write_state()
        self.state = server.AdminState(self.root, self.root / "static", self.config)
        self.http = server.Server(("127.0.0.1", 0), self.state)
        self.thread = threading.Thread(target=self.http.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        self.thread.start()
        self.addCleanup(self.shutdown)

    def shutdown(self):
        self.http.shutdown()
        self.http.server_close()
        self.thread.join(timeout=2)

    def write_state(self):
        path = self.root / "state.json"
        path.write_text(json.dumps(self.saved))
        path.chmod(0o640)

    def headers(self):
        return {"X-Elo-Admin-Proxy-Key": self.config["proxy_key"], "Origin": self.config["public_origin"], "X-CSRF-Token": self.state.csrf, "Content-Type": "application/json"}

    def request(self, method="GET", path="/admin/api/state", body=None, headers=None):
        connection = http.client.HTTPConnection(*self.http.server_address, timeout=3)
        try:
            connection.request(method, path, body, headers=self.headers() if headers is None else headers)
            response = connection.getresponse()
            return response.status, response.read(), dict(response.getheaders())
        finally:
            connection.close()

    def post(self, value=None, headers=None):
        return self.request("POST", "/admin/api/config", json.dumps(api_configuration() if value is None else value).encode(), headers)

    def test_proxy_authentication_applies_to_api_assets_and_unknown_routes(self):
        for path in ["/admin/", "/admin/style.css", "/admin/app.js", "/admin/en.json", "/admin/api/state", "/admin/api/config", "/admin/api/logs", "/unknown"]:
            self.assertEqual(self.request(path=path, headers={})[0], 403)
            self.assertEqual(self.request(path=path, headers={"X-Elo-Admin-Proxy-Key": "wrong"})[0], 403)
        status, body, headers = self.request()
        self.assertEqual(status, 200)
        self.assertNotIn(b"NEVER-RETURN-SECRET", body)
        self.assertEqual(json.loads(body)["csrf_token"], self.state.csrf)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        self.assertEqual(self.request(path="/admin/en.json")[0], 200)

    def test_logs_use_private_proxy_boundary_and_never_expose_reader_key(self):
        path = self.root / "diagnostics-read-key"
        path.write_text("r" * 40); path.chmod(0o600)
        status, body, _ = self.request()
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)["logs_available"])
        self.assertNotIn(b"r" * 40, body)
        with patch.object(self.state, "logs", return_value=(200, {"reports": [], "next": None})) as logs:
            self.assertEqual(self.request(path="/admin/api/logs?platform=ios", headers={})[0], 403)
            logs.assert_not_called()
            self.assertEqual(self.request(path="/admin/api/logs?platform=ios")[0], 200)
            logs.assert_called_once_with("platform=ios")
        with patch.object(self.state, "logs", side_effect=OSError("private details")):
            status, body, _ = self.request(path="/admin/api/logs")
            self.assertEqual(status, 503)
            self.assertNotIn(b"private details", body)

    def test_origin_and_csrf_are_required_before_any_enqueue(self):
        for key, value in [("Origin", None), ("Origin", "null"), ("Origin", "https://attacker.example"), ("X-CSRF-Token", None), ("X-CSRF-Token", "stale")]:
            headers = self.headers()
            if value is None:
                del headers[key]
            else:
                headers[key] = value
            self.assertEqual(self.post(headers=headers)[0], 403)
        self.assertEqual(list((self.root / "queue").glob("*.json")), [])

    def test_path_traversal_and_unknown_fields_are_rejected(self):
        for path in ["/admin/../state.json", "/admin/%2e%2e/state.json", "/admin/static/../../state.json", "/admin/api/jobs/../../state.json", "/admin/api/state?secret=x"]:
            self.assertEqual(self.request(path=path)[0], 404)
        self.assertEqual(self.post(api_configuration() | {"secret": "NEVER-RETURN-SECRET"})[0], 400)
        self.assertEqual(self.request("POST", "/admin/api/config", b'{"name":"secret","name":"other"}')[0], 400)
        self.assertEqual(self.request("POST", "/admin/api/config", b"x" * (schema.MAX_BODY + 1))[0], 413)
        headers = self.headers() | {"X-Extra": "x" * 17000}
        self.assertEqual(self.request(headers=headers)[0], 431)

    def test_job_is_private_durable_and_status_is_redacted(self):
        status, body, _ = self.post()
        self.assertEqual(status, 202)
        job = json.loads(body)
        path = self.root / "queue" / (job["id"] + ".json")
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(path.stat().st_nlink, 1)
        value = json.loads(path.read_text())
        self.assertEqual(value["configuration"], api_configuration())
        self.assertEqual(value["role"], "api")
        self.assertEqual(json.loads(self.request(path="/admin/api/jobs/" + job["id"])[1]), job)
        result = self.root / "status" / (job["id"] + ".json")
        result.write_text(json.dumps({"id": job["id"], "status": "failed", "error": "NEVER-RETURN-SECRET", "stderr": "NEVER-RETURN-SECRET"}))
        result.chmod(0o640)
        status, body, _ = self.request(path="/admin/api/jobs/" + job["id"])
        self.assertEqual(status, 200)
        self.assertNotIn(b"NEVER-RETURN-SECRET", body)
        self.assertEqual(json.loads(body)["status"], "failed")
        # A finished retained queue record does not block a new operation.
        self.assertEqual(self.post()[0], 202)

    def test_witness_secrets_exist_only_in_private_queue(self):
        self.state.role = "witness"
        self.saved = {"configuration": {"provider": "mega", "configured": True, "allowed_owners": [],
                                       "folder_link": "NEVER-RETURN-SECRET", "write_auth": "NEVER-RETURN-SECRET"}, "hosting": None}
        self.write_state()
        value = {"provider": "mega", "allowed_owners": ["a" * 64],
                 "folder_link": "https://mega.nz/folder/abcdefgh#" + "x" * 22, "write_auth": "y" * 32}
        status, body, _ = self.post(value)
        self.assertEqual(status, 202)
        for secret in (value["folder_link"], value["write_auth"]):
            self.assertNotIn(secret.encode(), body)
        job = json.loads(body)
        path = self.root / "queue" / (job["id"] + ".json")
        self.assertEqual(json.loads(path.read_text())["configuration"], value)
        status, body, _ = self.request()
        self.assertEqual(status, 200)
        self.assertNotIn(b"NEVER-RETURN-SECRET", body)
        self.assertNotIn(b"write_auth", body)
        self.assertNotIn(b"folder_link", body)

    def test_duplicate_proxy_header_is_rejected(self):
        connection = http.client.HTTPConnection(*self.http.server_address, timeout=3)
        try:
            connection.putrequest("GET", "/admin/api/state")
            connection.putheader("X-Elo-Admin-Proxy-Key", self.config["proxy_key"])
            connection.putheader("X-Elo-Admin-Proxy-Key", self.config["proxy_key"])
            connection.endheaders()
            response = connection.getresponse()
            self.assertEqual(response.status, 403)
            response.read()
        finally:
            connection.close()

    def test_concurrent_submissions_accept_exactly_one_pending_job(self):
        with ThreadPoolExecutor(max_workers=6) as executor:
            statuses = list(executor.map(lambda _: self.post()[0], range(6)))
        self.assertEqual(statuses.count(202), 1)
        self.assertEqual(statuses.count(409), 5)
        self.assertEqual(len(list((self.root / "queue").glob("*.json"))), 1)

    def test_symlinked_state_or_job_is_not_read(self):
        (self.root / "state.json").unlink()
        outside = self.root / "private.json"
        outside.write_text('"NEVER-RETURN-SECRET"')
        (self.root / "state.json").symlink_to(outside)
        status, body, _ = self.request()
        self.assertEqual(status, 503)
        self.assertNotIn(b"NEVER-RETURN-SECRET", body)
        identifier = "a" * 32
        (self.root / "status" / (identifier + ".json")).symlink_to(outside)
        status, body, _ = self.request(path="/admin/api/jobs/" + identifier)
        self.assertEqual(status, 503)
        self.assertNotIn(b"NEVER-RETURN-SECRET", body)


if __name__ == "__main__":
    unittest.main()
