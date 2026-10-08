import unittest
import install


class ProxyTests(unittest.TestCase):
    def test_only_exact_ingestion_route_is_public_and_repeated_generation_is_stable(self):
        previous = 'https://host.example {\n\thandle {\n\t\treverse_proxy 127.0.0.1:18900\n\t}\n}\n'
        updated = install.proxy_config(previous)
        self.assertEqual(install.proxy_config(updated), updated)
        self.assertIn('path /diagnostics/v1/errors\n', updated)
        self.assertIn('respond @not_post 405', updated)
        self.assertNotIn('/reports', updated)
        self.assertNotIn('/admin', updated)
        self.assertIn('header_up -Authorization', updated)
        self.assertIn('reverse_proxy 127.0.0.1:18900', updated)

    def test_damaged_proxy_marker_fails_closed(self):
        with self.assertRaises(ValueError): install.proxy_config('https://example {\n' + install.BEGIN + '}')


if __name__ == '__main__': unittest.main()
