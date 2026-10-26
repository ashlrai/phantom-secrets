"""Hermetic tests for the keyless emitter. Run with python3 -m unittest discover -s examples -p test_posthog_capture.py."""

import contextlib
import importlib.util
import io
import http.client
import json
import os
from pathlib import Path
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "posthog_capture", Path(__file__).with_name("posthog-capture.py")
)
emitter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(emitter)


class CaptureTests(unittest.TestCase):
    def serve(self, result="ok", status=200, malformed=False, missing=False):
        received = []

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                received.append((self.path, self.headers, body))
                event_id = body["batch"][0]["uuid"]
                self.send_response(status)
                if status == 302:
                    self.send_header("Location", "/redirect-must-not-be-followed")
                self.end_headers()
                payload = {"results": {} if missing else {event_id: {"result": result}}}
                self.wfile.write(
                    b"invalid JSON" if malformed else json.dumps(payload).encode()
                )

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join)
        self.addCleanup(server.shutdown)
        return server, received

    def invoke(self, server, path_token=True):
        stdout, stderr = io.StringIO(), io.StringIO()
        with (
            patch.dict(
                os.environ,
                {
                    "POSTHOG_BASE_URL": f"http://127.0.0.1:{server.server_port}/posthog_fleet"
                    + ("/_phantom/abcdef/" if path_token else ""),
                    "PHANTOM_PROXY_TOKEN": "fake-local-session-token",
                    "HTTP_PROXY": "http://127.0.0.1:1",
                },
                clear=True,
            ),
            patch("sys.argv", ["posthog-capture.py", "fleet.work", "test-fleet"]),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            code = emitter.main()
        return code, stdout.getvalue(), stderr.getvalue()

    def test_accepts_ok_and_warning_without_reading_api_key(self):
        for result in ["ok", "warning"]:
            with self.subTest(result=result):
                server, received = self.serve(result=result)
                code, stdout, stderr = self.invoke(server)
                self.assertEqual(code, 0)
                self.assertIn("HTTP 200, event accepted", stdout)
                self.assertEqual(stderr, "")
                self.assertEqual(len(received), 1)
                path, headers, body = received[0]
                self.assertTrue(path.endswith("/i/v1/analytics/events"))
                self.assertEqual(
                    headers["x-phantom-proxy-token"], "fake-local-session-token"
                )
                self.assertIsNone(headers.get("Authorization"))
                for header in [
                    "PostHog-Sdk-Info",
                    "PostHog-Attempt",
                    "PostHog-Request-Id",
                    "PostHog-Request-Timestamp",
                    "Content-Type",
                    "User-Agent",
                ]:
                    self.assertIsNotNone(headers.get(header))
                self.assertEqual(body["batch"][0]["event"], "fleet.work")
                self.assertNotIn("api_key", json.dumps(body))

    def test_rejects_unsuccessful_event_results(self):
        for result in ["drop", "retry", "unknown"]:
            with self.subTest(result=result):
                server, _ = self.serve(result=result)
                code, stdout, stderr = self.invoke(server)
                self.assertEqual(code, 1)
                self.assertEqual(stdout, "")
                self.assertNotIn("abcdef", stderr)
                self.assertNotIn("fake-local-session-token", stderr)

    def test_header_only_mode(self):
        server, received = self.serve()
        self.assertEqual(self.invoke(server, path_token=False)[0], 0)
        self.assertEqual(received[0][0], "/posthog_fleet/i/v1/analytics/events")
        self.assertEqual(
            received[0][1]["x-phantom-proxy-token"], "fake-local-session-token"
        )

    def test_malformed_http_response_cannot_expose_session_metadata(self):
        server, _ = self.serve()
        with patch.object(
            emitter.urllib.request.OpenerDirector,
            "open",
            side_effect=http.client.BadStatusLine("abcdef fake-local-session-token"),
        ):
            code, stdout, stderr = self.invoke(server)
        self.assertEqual(code, 1)
        self.assertEqual(stdout, "")
        self.assertNotIn("abcdef", stderr)
        self.assertNotIn("fake-local-session-token", stderr)

    def test_rejects_malformed_and_missing_results(self):
        for kwargs in [{"malformed": True}, {"missing": True}]:
            server, _ = self.serve(**kwargs)
            self.assertEqual(self.invoke(server)[0], 1)

    def test_does_not_follow_redirects_or_expose_url(self):
        server, received = self.serve(status=302)
        code, stdout, stderr = self.invoke(server)
        self.assertEqual(code, 1)
        self.assertEqual(len(received), 1)
        self.assertEqual(stdout, "")
        self.assertNotIn("abcdef", stderr)
        self.assertNotIn("127.0.0.1", stderr)

    def test_rejects_non_proxy_destinations_before_network(self):
        for url in [
            "https://us.i.posthog.com",
            "http://attacker.invalid/posthog_fleet",
            "http://127.0.0.1:1234/other",
            "http://127.0.0.1:1234/posthog_fleet?token=sensitive",
        ]:
            with (
                patch.dict(os.environ, {"POSTHOG_BASE_URL": url}, clear=True),
                self.assertRaises(ValueError),
            ):
                emitter.capture("test", "test", {})


if __name__ == "__main__":
    unittest.main()
