"""Localhost-only codec server sketch for Temporal tooling.

DESIGN, untested against the Temporal Web UI or a server. Binds 127.0.0.1
only and decodes sensitive data in one call, so never expose it.

CORS is off by default: no CORS headers are sent, so a browser page on another
origin cannot read responses (the Temporal CLI, which sends no Origin header,
works as before). To let the Temporal Web UI call it, opt in with an exact
origin list in PHANTOM_TEMPORAL_CODEC_CORS_ORIGINS (see cors.py). A request
that carries an Origin not on the list is refused with 403 and no CORS headers.
"""

import asyncio
import os
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit

from google.protobuf import json_format
from temporalio.api.common.v1 import Payloads

from codec import EncryptionCodec, load_keys
from cors import CODEC_PATHS, CorsPolicy

MAX_BODY_BYTES = 1_000_000


def make_handler(codec: EncryptionCodec, cors: CorsPolicy = CorsPolicy()):
    class Handler(BaseHTTPRequestHandler):
        def _plain(self, status: int, extra=()):
            self.send_response(status)
            for name, value in extra:
                self.send_header(name, value)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def _route(self) -> str:
            # The Temporal Web UI (2.54.1, checked) calls
            # /decode?preserveStorageRefs=true, so route on the path only.
            return urlsplit(self.path).path

        def do_OPTIONS(self):
            decision = cors.for_preflight(
                self._route(),
                self.headers.get("Origin"),
                self.headers.get("Access-Control-Request-Method"),
                self.headers.get("Access-Control-Request-Headers"),
            )
            self._plain(204 if decision.allowed else 403, decision.headers)

        def do_POST(self):
            route = self._route()
            if route not in CODEC_PATHS:
                self.send_error(404)
                return
            decision = cors.for_request(self.headers.get("Origin"))
            if not decision.allowed:
                self._plain(403)
                return
            # Do not let negative lengths turn read(n) into an unbounded read.
            # This HTTP server does not implement chunked request decoding.
            lengths = self.headers.get_all("Content-Length", [])
            if self.headers.get_all("Transfer-Encoding") or len(lengths) > 1:
                self.send_error(400, "ambiguous or unsupported request framing")
                return
            if not lengths:
                self.send_error(411, "Content-Length is required")
                return
            if not re.fullmatch(r"[0-9]+", lengths[0]):
                self.send_error(400, "invalid Content-Length")
                return
            # Compare decimal strings before int(), including huge headers that
            # exceed Python's integer-conversion digit limit.
            digits = lengths[0].lstrip("0") or "0"
            limit = str(MAX_BODY_BYTES)
            if len(digits) > len(limit) or (len(digits) == len(limit) and digits > limit):
                self.send_error(413)
                return
            length = int(digits)
            try:
                body = json_format.Parse(self.rfile.read(length), Payloads())
            except json_format.ParseError:
                self.send_error(400, "body is not a Payloads JSON document")
                return
            fn = codec.encode if route == "/encode" else codec.decode
            try:
                result = asyncio.run(fn(body.payloads))
            except ValueError:
                self.send_error(400, "cannot process payloads")
                return
            out = json_format.MessageToJson(Payloads(payloads=result)).encode()
            self.send_response(200)
            for name, value in decision.headers:
                self.send_header(name, value)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

        def log_message(self, *args):  # no payload data in logs
            pass

    return Handler


if __name__ == "__main__":
    # Prefer PHANTOM_TEMPORAL_CODEC_KEYS_FD (inherited pipe) over key variables.
    keys = load_keys(os.environ)
    codec = EncryptionCodec(keys, os.environ["PHANTOM_TEMPORAL_CODEC_KEY_ID"])
    # Fails at startup on a wildcard, pattern or malformed origin.
    # Authorization stays off: this sketch does not check credentials, so it
    # must not invite browsers to send them.
    cors = CorsPolicy.from_env(os.environ)
    HTTPServer(("127.0.0.1", 8081), make_handler(codec, cors)).serve_forever()
