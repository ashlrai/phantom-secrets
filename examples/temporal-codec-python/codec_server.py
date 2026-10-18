"""Localhost-only codec server sketch for the Temporal Web UI.

DESIGN, untested against the Temporal Web UI or a server. Binds 127.0.0.1
only, sends no CORS headers (so a browser UI on another origin cannot call it
until you add an explicit allow-list yourself), and requires no values from
Phantom. It decodes sensitive data in one call, so never expose it.
"""

import asyncio
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

from google.protobuf import json_format
from temporalio.api.common.v1 import Payloads

from codec import EncryptionCodec, keys_from_env


def make_handler(codec: EncryptionCodec):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            if self.path not in ("/encode", "/decode"):
                self.send_error(404)
                return
            length = int(self.headers.get("Content-Length", "0"))
            if length > 1_000_000:
                self.send_error(413)
                return
            body = json_format.Parse(self.rfile.read(length), Payloads())
            fn = codec.encode if self.path == "/encode" else codec.decode
            try:
                result = asyncio.run(fn(body.payloads))
            except ValueError:
                self.send_error(400, "cannot process payloads")
                return
            out = json_format.MessageToJson(Payloads(payloads=result)).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(out)

        def log_message(self, *args):  # no payload data in logs
            pass

    return Handler


if __name__ == "__main__":
    keys = keys_from_env()
    codec = EncryptionCodec(keys, os.environ["PHANTOM_TEMPORAL_CODEC_KEY_ID"])
    HTTPServer(("127.0.0.1", 8081), make_handler(codec)).serve_forever()
