"""Isolation checks for the removable test hosting provisioner."""

import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("test_host_provisioner", Path(__file__).with_name("test_host.py"))
host = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host)


class TestHostingIsolation(unittest.TestCase):
    def test_origin_keeps_hostname_but_uses_a_distinct_https_service(self):
        self.assertEqual(host.test_origin("https://api.example.test"), "https://api.example.test:9443")
        for value in ("http://api.example.test", "https://api.example.test:443", "https://api.example.test/", "https://user@api.example.test"):
            with self.assertRaises(ValueError):
                host.test_origin(value)

    def test_compose_has_separate_databases_and_only_readonly_shared_certificate(self):
        state = Path("/srv/elo-api-test")
        tls = Path("/srv/elo-api/proxy/data/certificates/example.test")
        uids = {"api": 21001, "proxy": 21004, "wake": 21006, "calls": 21007}
        config = host.compose_configuration(state, tls, "https://api.example.test:9443", "1.0.6-1136", uids)
        self.assertEqual(config["name"], "elo-api-test")
        self.assertEqual(set(config["services"]), {"api", "wake", "calls", "proxy"})
        for role, service in config["services"].items():
            self.assertTrue(service["read_only"])
            self.assertEqual(service["cap_drop"], ["ALL"])
            self.assertNotIn("ports", service)
            if role == "proxy":
                self.assertEqual(service["cap_add"], ["NET_BIND_SERVICE"])
            else:
                self.assertNotIn("cap_add", service)
            for volume in service["volumes"]:
                if volume["source"] == str(tls):
                    self.assertEqual(role, "proxy")
                    self.assertTrue(volume["read_only"])
                else:
                    self.assertTrue(Path(volume["source"]).is_relative_to(state))
        self.assertIn("127.0.0.1:19900", config["services"]["api"]["command"])
        self.assertIn("127.0.0.1:8878", config["services"]["wake"]["command"])
        self.assertIn("/opt/elo/wake.py", config["services"]["wake"]["command"])

    def test_proxy_does_not_bind_public_ports_or_request_new_certificates(self):
        value = host.proxy_configuration("https://api.example.test:9443", "api.example.test").decode()
        self.assertIn("auto_https off", value)
        self.assertIn("protocols h1 h2", value)
        self.assertIn("https://api.example.test:9443 {", value)
        self.assertIn("tls /etc/caddy/public-tls/api.example.test.crt /etc/caddy/public-tls/api.example.test.key", value)
        self.assertIn("127.0.0.1:19900", value)
        self.assertIn("127.0.0.1:8878", value)
        self.assertIn("127.0.0.1:19920", value)
        self.assertIn("@calls path /calls/v1/connect /calls/v1/state /calls/v1/health\n", value)
        self.assertNotIn("/calls/*", value)
        self.assertNotIn("/calls/v1/*", value)
        self.assertNotIn("/internal/calls", value)
        for public_listener in ("127.0.0.1:18900", "127.0.0.1:18901", "127.0.0.1:18920", "127.0.0.1:8788", "127.0.0.1:7880"):
            self.assertNotIn(public_listener, value)

    def test_shared_media_endpoints_and_credentials_cannot_drift(self):
        media = {"url": "wss://api.example.test/media", "api_url": "http://127.0.0.1:7880",
                 "api_key": "elo-private", "api_secret": "a" * 64, "turn_secret": "b" * 64,
                 "turn_urls": ["turn:api.example.test:3478?transport=udp", "turn:api.example.test:3478?transport=tcp"]}
        copy = host.media_configuration(media, "https://api.example.test")
        self.assertEqual(copy, media)
        self.assertIsNot(copy, media)
        self.assertIsNot(copy["turn_urls"], media["turn_urls"])
        for key, changed in (("url", "wss://api.example.test:9443/media"), ("api_url", "http://127.0.0.1:19900"), ("api_secret", "")):
            with self.assertRaises(ValueError):
                host.media_configuration(dict(media, **{key: changed}), "https://api.example.test")


if __name__ == "__main__":
    unittest.main()
