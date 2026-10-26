# Temporal payload codec sketch (untested design)

Status: sketch. The codec's round trip, key rotation by key id, tamper rejection and key-length check are unit tested with fake keys (`python -m unittest`), as are key delivery (`test_key_delivery.py`) and the codec server's CORS policy, including HTTP requests to the handler on 127.0.0.1 (`test_cors.py`). It was run once end to end against a local `temporal server start-dev` (CLI v1.9.1) with a worker under `phantom exec`, using `e2e_worker.py` and `e2e_start.py`; the steps and results are in [docs/temporal.md](../../docs/temporal.md). The Web UI rendering itself was not checked. Read [docs/temporal.md](../../docs/temporal.md) first. Temporal is optional; Phantom does not depend on it.

What it does: encrypts each Temporal payload with AES-256-GCM, records a key id in payload metadata so keys can rotate, and offers a localhost-only codec server (127.0.0.1:8081) for decoding in tooling.

Codec server CORS:

- Off by default. No CORS headers are sent, which suits the Temporal CLI (`--codec-endpoint`). A request that carries an `Origin` header not on the list is refused with 403 and no CORS headers.
- To let a browser page such as the Temporal Web UI call it, set `PHANTOM_TEMPORAL_CODEC_CORS_ORIGINS` to a comma-separated list of exact origins, for example `http://localhost:8080`. Each entry must be exactly `scheme://host[:port]` with `http` or `https`. `*`, `null`, patterns, paths and user info are refused at startup. Matching compares scheme, host and port (a default port matches whether written or not).
- The origin is the exact URL the browser opened: `http://localhost:8233` and `http://127.0.0.1:8233` are different. Leave the UI's codec "pass access token" and "include credentials" settings off; this sketch supports neither.
- Allowed origins get only what the codec protocol needs: `POST` (and the `OPTIONS` preflight) on `/encode` and `/decode`, with `Content-Type` and `X-Namespace`. No credentials are allowed. The `Authorization` header is not allowed because this sketch does not check it.

Key delivery (keep the key out of argv, environment dumps and workflow history):

- Preferred: set `PHANTOM_TEMPORAL_CODEC_KEYS_FD` to the number of an inherited pipe or socket. The process reads it once at startup, one `<ID>=<base64 32-byte key>` per line, then closes it so later child processes cannot read it. A regular file or a terminal is refused. The variable holds only the fd number.
- Fallback: `PHANTOM_TEMPORAL_CODEC_KEY_<ID>` variables (base64, 32 bytes). Weaker: the values stay in the process environment, where same-user tools can read them and child processes inherit them. Setting both is refused.
- `PHANTOM_TEMPORAL_CODEC_KEY_ID` names the current key. Key ids are written to payload metadata and so to workflow history; use plain labels such as `2026-10`, never key material.
- Whatever writes the pipe must not take the key on its own command line. Phantom has no command for this: `phantom exec` exports placeholders, and `phantom reveal` needs an interactive terminal.

What it does not do:

- It does not make it safe to put a raw secret value in a workflow input, result, signal, memo or failure. Do not do that. Pass names or opaque ids.
- It does not get its key from the Phantom proxy. The proxy injects real credentials into outbound provider requests; it does not hand key material to a process. Deliver the codec key yourself as described under Key delivery.
- It was not reviewed by a cryptographer. Do not use it for production data.

Run the tests (use a throwaway virtual environment):

```sh
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python -m unittest
```

CI runs the same tests in the `Temporal codec example tests` job whenever this directory or a workflow changes, and on every push to `main`. It installs the exact versions in `requirements-ci.txt` (wheels only, every file hash-checked) and fails if any test is skipped.

Use `temporal server start-dev` only for experiments, and never put real secrets in it.
