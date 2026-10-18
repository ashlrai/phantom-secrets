#!/usr/bin/env python3
"""Mock OpenAI-compatible upstream for the LiteLLM verification.

Records each request (path, headers, body) as one JSON line in the file given
as argv[2] and answers with a canned chat completion. Binds 127.0.0.1 only.
Usage: mock_upstream.py PORT RECORD_FILE
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

port, record_file = int(sys.argv[1]), sys.argv[2]


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("content-length", 0))
        body = self.rfile.read(length).decode("utf-8", "replace")
        with open(record_file, "a") as f:
            f.write(json.dumps({"path": self.path, "headers": dict(self.headers), "body": body}) + "\n")
        out = json.dumps({
            "id": "mock-1", "object": "chat.completion", "created": 0, "model": "mock-model",
            "choices": [{"index": 0, "finish_reason": "stop",
                         "message": {"role": "assistant", "content": "mock reply"}}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3},
        }).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


HTTPServer(("127.0.0.1", port), Handler).serve_forever()
