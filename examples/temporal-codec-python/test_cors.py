"""CORS tests for the codec server sketch.

Policy tests need only the standard library. The HTTP tests start the real
handler on 127.0.0.1 and need the example's requirements (temporalio).
"""

import asyncio
import http.client
import json
import threading
import unittest
from http.server import HTTPServer

from cors import CorsConfigError, CorsPolicy, parse_allowed_origins

UI = "http://localhost:8233"


class OriginConfigTests(unittest.TestCase):
    def test_default_is_no_origins(self):
        self.assertEqual(parse_allowed_origins(None), frozenset())
        self.assertEqual(parse_allowed_origins("  "), frozenset())
        self.assertFalse(CorsPolicy().origin_allowed(UI))

    def test_wildcards_and_patterns_rejected(self):
        for bad in [
            "*",
            "https://*",
            "https://*.example.com",
            "https://example.*",
            "http://localhost:*",
            "https://exa?ple.com",
            "^https://example\\.com$",
            "https://(a|b).example.com",
            "https://[a-z].example.com",
            "null",
        ]:
            with self.subTest(bad=bad), self.assertRaises(CorsConfigError):
                parse_allowed_origins(bad)
        with self.assertRaises(CorsConfigError):
            parse_allowed_origins(f"{UI},*")

    def test_non_origins_rejected(self):
        for bad in [
            "localhost:8233",
            "ftp://localhost",
            "http://localhost:8233/",
            "http://localhost:8233/path",
            "http://localhost:8233?x=1",
            "http://localhost:8233#f",
            "http://user@localhost:8233",
            "http://localhost:99999",
            "http://",
        ]:
            with self.subTest(bad=bad), self.assertRaises(CorsConfigError):
                parse_allowed_origins(bad)

    def test_exact_scheme_host_port_match(self):
        policy = CorsPolicy(parse_allowed_origins(f"{UI}, https://cloud.temporal.io"))
        self.assertTrue(policy.origin_allowed(UI))
        self.assertTrue(policy.origin_allowed("https://cloud.temporal.io"))
        # The default port is the same origin, written or not.
        self.assertTrue(policy.origin_allowed("https://cloud.temporal.io:443"))
        for other in [
            "https://localhost:8233",  # scheme differs
            "http://localhost:8234",  # port differs
            "http://localhost",  # port differs (80)
            "http://127.0.0.1:8233",  # host differs
            "https://evil.cloud.temporal.io",
            "https://cloud.temporal.io.evil.example",
            "http://localhost:8233/",
            "null",
            "",
        ]:
            with self.subTest(origin=other):
                self.assertFalse(policy.origin_allowed(other))


class PreflightPolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy = CorsPolicy(parse_allowed_origins(UI))

    def test_allowed_preflight_lists_only_protocol_needs(self):
        d = self.policy.for_preflight("/decode", UI, "POST", "content-type, x-namespace")
        self.assertTrue(d.allowed)
        h = dict(d.headers)
        self.assertEqual(h["Access-Control-Allow-Origin"], UI)
        self.assertEqual(h["Access-Control-Allow-Methods"], "POST, OPTIONS")
        self.assertEqual(h["Access-Control-Allow-Headers"], "Content-Type, X-Namespace")
        self.assertNotIn("Access-Control-Allow-Credentials", h)

    def test_authorization_only_when_enabled(self):
        self.assertFalse(self.policy.for_preflight("/decode", UI, "POST", "authorization").allowed)
        with_auth = CorsPolicy(parse_allowed_origins(UI), allow_authorization=True)
        d = with_auth.for_preflight("/decode", UI, "POST", "Content-Type, X-Namespace, Authorization")
        self.assertTrue(d.allowed)
        self.assertEqual(dict(d.headers)["Access-Control-Allow-Headers"], "Content-Type, X-Namespace, Authorization")

    def test_refused_preflights_carry_no_headers(self):
        cases = [
            ("/decode", "http://evil.example", "POST", "content-type"),
            ("/decode", None, "POST", "content-type"),
            ("/decode", UI, "GET", "content-type"),
            ("/decode", UI, "DELETE", ""),
            ("/decode", UI, "POST", "content-type, x-custom"),
            ("/admin", UI, "POST", "content-type"),
        ]
        for path, origin, method, headers in cases:
            with self.subTest(path=path, origin=origin, method=method, headers=headers):
                d = self.policy.for_preflight(path, origin, method, headers)
                self.assertFalse(d.allowed)
                self.assertEqual(d.headers, ())


try:
    from codec import EncryptionCodec
    from codec_server import make_handler

    HAVE_SERVER_DEPS = True
except ImportError:  # temporalio not installed
    HAVE_SERVER_DEPS = False


@unittest.skipUnless(HAVE_SERVER_DEPS, "needs the example requirements (temporalio)")
class ServerCorsTests(unittest.TestCase):
    def start(self, policy):
        codec = EncryptionCodec({"a": bytes(range(32))}, "a")
        server = HTTPServer(("127.0.0.1", 0), make_handler(codec, policy))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server.server_address[1]

    def request(self, port, method, path, headers, body=b""):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        result = resp.status, {k.lower(): v for k, v in resp.getheaders()}, data
        conn.close()
        return result

    BODY = json.dumps(
        {"payloads": [{"metadata": {"encoding": "anNvbi9wbGFpbg=="}, "data": "eyJuYW1lIjoiWCJ9"}]}
    ).encode()

    def post(self, port, origin=None):
        headers = {"Content-Type": "application/json", "X-Namespace": "default"}
        if origin is not None:
            headers["Origin"] = origin
        return self.request(port, "POST", "/encode", headers, self.BODY)

    def test_no_cors_by_default(self):
        port = self.start(CorsPolicy())
        status, headers, _ = self.post(port)  # CLI: no Origin header
        self.assertEqual(status, 200)
        self.assertFalse(any(k.startswith("access-control-") for k in headers))
        status, headers, _ = self.post(port, UI)
        self.assertEqual(status, 403)
        self.assertFalse(any(k.startswith("access-control-") for k in headers))

    def test_allowed_origin(self):
        port = self.start(CorsPolicy(parse_allowed_origins(UI)))
        status, headers, body = self.post(port, UI)
        self.assertEqual(status, 200)
        self.assertEqual(headers["access-control-allow-origin"], UI)
        self.assertEqual(headers["vary"], "Origin")
        self.assertIn("payloads", json.loads(body))

    def test_refused_origin_gets_no_cors_headers_and_no_payload(self):
        port = self.start(CorsPolicy(parse_allowed_origins(UI)))
        status, headers, body = self.post(port, "http://evil.example")
        self.assertEqual(status, 403)
        self.assertFalse(any(k.startswith("access-control-") for k in headers))
        self.assertEqual(body, b"")

    def test_preflight_allowed_and_refused(self):
        port = self.start(CorsPolicy(parse_allowed_origins(UI)))
        ok = {"Origin": UI, "Access-Control-Request-Method": "POST",
              "Access-Control-Request-Headers": "content-type,x-namespace"}
        status, headers, _ = self.request(port, "OPTIONS", "/decode", ok)
        self.assertEqual(status, 204)
        self.assertEqual(headers["access-control-allow-origin"], UI)
        self.assertEqual(headers["access-control-allow-methods"], "POST, OPTIONS")
        self.assertEqual(headers["access-control-allow-headers"], "Content-Type, X-Namespace")
        for bad in [
            dict(ok, Origin="http://evil.example"),
            dict(ok, **{"Access-Control-Request-Method": "PUT"}),
            dict(ok, **{"Access-Control-Request-Headers": "content-type,authorization"}),
        ]:
            with self.subTest(bad=bad):
                status, headers, _ = self.request(port, "OPTIONS", "/decode", bad)
                self.assertEqual(status, 403)
                self.assertFalse(any(k.startswith("access-control-") for k in headers))


if __name__ == "__main__":
    unittest.main()
