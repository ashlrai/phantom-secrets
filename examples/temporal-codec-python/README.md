# Temporal payload codec sketch (untested design)

Status: sketch. The codec's round trip, key rotation by key id, tamper rejection and key-length check are unit tested with fake keys (`python -m unittest`). It has not been run against a Temporal server or the Temporal Web UI, and the codec server is untested. Read [docs/temporal.md](../../docs/temporal.md) first. Temporal is optional; Phantom does not depend on it.

What it does: encrypts each Temporal payload with AES-256-GCM, records a key id in payload metadata so keys can rotate, and offers a localhost-only codec server (127.0.0.1:8081, no CORS headers) for decoding in tooling.

What it does not do:

- It does not make it safe to put a raw secret value in a workflow input, result, signal, memo or failure. Do not do that. Pass names or opaque ids.
- It does not get its key from the Phantom proxy. The proxy injects real credentials into outbound provider requests; it does not hand key material to a process. The codec key must be available to the worker and the codec server as an environment variable (`PHANTOM_TEMPORAL_CODEC_KEY_<ID>`, base64, 32 bytes). How to deliver that key without a file on disk is an open question, not solved here.
- It was not reviewed by a cryptographer. Do not use it for production data.

Run the tests (use a throwaway virtual environment):

```sh
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python -m unittest
```

Use `temporal server start-dev` only for experiments, and never put real secrets in it.
