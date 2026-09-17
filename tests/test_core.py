import json
import tempfile
import unittest
from pathlib import Path

from app.core import Route, RouteManager, extract_active_routes, password_digest, password_hash_is_valid, secure_compare_password


class FakeCaddy:
    def __init__(self):
        self.calls = 0
        self.error = None

    def validate_and_load(self, caddyfile: str) -> None:
        self.calls += 1
        if self.error:
            raise RuntimeError(self.error)
        if "sites.d/*.caddy" not in caddyfile:
            raise RuntimeError("falta import")

    def list_active_routes(self):
        return []


class RouteTests(unittest.TestCase):
    def test_password_hash(self):
        encoded = password_digest("correct horse battery staple")
        self.assertTrue(password_hash_is_valid(encoded))
        self.assertTrue(secure_compare_password("correct horse battery staple", encoded))
        self.assertFalse(secure_compare_password("wrong", encoded))

    def test_render_http_route(self):
        route = Route.from_mapping({
            "id": "plex",
            "name": "Plex",
            "domain": "plex.example.com",
            "scheme": "http",
            "upstream_host": "10.0.0.20",
            "upstream_port": 32400,
        })
        rendered = route.render()
        self.assertIn("@cc_plex host plex.example.com", rendered)
        self.assertIn("reverse_proxy http://10.0.0.20:32400", rendered)
        self.assertNotIn("tls_insecure_skip_verify\n", rendered)

    def test_rejects_caddyfile_injection(self):
        with self.assertRaises(ValueError):
            Route.from_mapping({
                "id": "bad",
                "name": "Bad",
                "domain": "example.com\nrespond hacked",
                "upstream_host": "localhost",
                "upstream_port": 80,
            })

    def test_extracts_nested_active_reverse_proxies(self):
        config = {
            "apps": {"http": {"servers": {"srv0": {"routes": [{
                "match": [{"host": ["*.example.com"]}],
                "handle": [{"handler": "subroute", "routes": [{
                    "match": [{"host": ["plex.example.com"]}],
                    "handle": [{"handler": "reverse_proxy", "upstreams": [{"dial": "192.168.1.2:32400"}]}],
                }, {
                    "match": [{"host": ["secure.example.com"]}],
                    "handle": [{
                        "handler": "reverse_proxy",
                        "transport": {"protocol": "http", "tls": {"insecure_skip_verify": True}},
                        "upstreams": [{"dial": "192.168.1.10:9443"}],
                    }],
                }]}],
            }]}}}}}
        routes = extract_active_routes(config)
        self.assertEqual(2, len(routes))
        self.assertEqual("plex.example.com", routes[0].domain)
        self.assertEqual("192.168.1.2:32400", routes[0].upstream)
        self.assertEqual("https", routes[1].scheme)
        self.assertTrue(routes[1].tls_insecure_skip_verify)


class ManagerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.sites = root / "sites.d"
        self.caddyfile = root / "Caddyfile"
        self.caddyfile.write_text("example.com {\n import /etc/caddy/sites.d/*.caddy\n}\n")
        self.fake = FakeCaddy()
        self.manager = RouteManager(
            self.sites,
            self.caddyfile,
            root / "backups",
            root / "audit.jsonl",
            self.fake,
        )
        self.route = Route.from_mapping({
            "id": "plex",
            "name": "Plex",
            "domain": "plex.example.com",
            "scheme": "http",
            "upstream_host": "10.0.0.20",
            "upstream_port": 32400,
        })

    def tearDown(self):
        self.temp.cleanup()

    def test_save_list_and_delete(self):
        self.manager.save(self.route, "admin")
        self.assertEqual([self.route], self.manager.list_routes())
        self.assertEqual(self.fake.calls, 1)
        self.manager.delete("plex", "admin")
        self.assertEqual([], self.manager.list_routes())
        records = [json.loads(line) for line in self.manager.audit_path.read_text().splitlines()]
        self.assertEqual([True, True], [record["success"] for record in records])

    def test_failed_reload_restores_previous_file(self):
        self.manager.save(self.route, "admin")
        original = (self.sites / "plex.caddy").read_text()
        self.fake.error = "syntax error"
        changed = Route.from_mapping({**self.route.__dict__, "upstream_port": 9999})
        with self.assertRaises(RuntimeError):
            self.manager.save(changed, "admin")
        self.assertEqual(original, (self.sites / "plex.caddy").read_text())


if __name__ == "__main__":
    unittest.main()
