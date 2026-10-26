# Temporal workers with no secrets on disk (optional)

Status: guidance only. Phantom does not depend on Temporal, ships no Temporal code, and has not been tested against a Temporal server in this repository. Items marked DESIGN are untested proposals. Facts about Temporal come from the Temporal documentation and releases pages read on 2026-10-18 and rechecked on 2026-10-19, and may change; check the linked pages. A payload codec sketch lives in [`examples/temporal-codec-python`](../examples/temporal-codec-python/README.md) (unit tested with fake keys only).

## What this is for

[Temporal](https://github.com/temporalio/temporal) (MIT licensed) runs durable workflows: a workflow resumes at the failed step after a crash. Teams that already run Temporal for agent or rotation workflows can use Phantom so that the worker process does not need real credentials in a checked-in file. Phantom stays a separate, optional layer. Nothing in Phantom requires Temporal, and nothing here changes how Phantom works.

## Rule 1: no raw secret values in Temporal payloads

Never put a real secret value in any of these, because Temporal stores them in workflow history:

- workflow, activity, or child workflow inputs and results
- signal inputs, query inputs and results, memo, and headers
- application error messages and stack traces (failure text is stored too)

Pass secret names or opaque identifiers instead, and let the activity use the credential that `phantom exec` gave its own process. A `phm_` placeholder is not a real key, so it is safe in history, but prefer the name: `phantom exec` hands each run fresh session placeholders that stop working when that run ends, so a placeholder recorded in history will not resolve when the workflow is replayed or retried on another worker.

A payload codec can encrypt payloads, but it is a second layer. It is not a reason to put a raw value in a payload.

## Rule 2: start workers through Phantom

Run the worker under `phantom exec` so that it receives placeholder tokens and a local proxy, and real values stay in the vault:

```sh
phantom exec -- python worker.py
```

The worker's own connection settings (for example a Temporal Cloud API key or an mTLS client key) should come from the environment that Phantom provides, not from a file in the repository. Which Temporal client settings can be delivered this way depends on how your worker reads its configuration and on which services Phantom has routes for. Check `phantom exec` behavior in [Getting started](getting-started.md) before relying on it. DESIGN: not tested with a Temporal worker here.

Activities that call model or API providers should send requests through the Phantom proxy base URLs that `phantom exec` sets, so the provider key is injected outside the worker process.

## Rule 3: lock down the Temporal server

**Configure an Authorizer.** The Temporal self-hosted security guide warns that if you do not configure an `Authorizer`, the server uses the default `noopAuthorizer`, which allows every API request with no authentication or access control: anyone who can reach the server can call any API, including administrative ones (https://docs.temporal.io/self-hosted-guide/security). The guide says to configure an `Authorizer` with a matching `ClaimMapper` (server options `temporal.WithAuthorizer` and `temporal.WithClaimMapper`).

- Do not expose a development server to a network. `temporal server start-dev` is for local experiments only and must never hold real secrets.
- For anything shared, configure mTLS (`internode` and `frontend`) plus the Authorizer and ClaimMapper.

**Pin the server version.** Use Temporal Server v1.32.1 or newer. v1.32.1 was published on 2026-10-08 and was the newest release on the v1.32 line when this page was checked (https://github.com/temporalio/temporal/releases/tag/v1.32.1). Its release notes list bug fixes and no security advisories, so the pin is a current baseline, not a fix for a known issue. Check the releases page for newer patches before you upgrade.

## Rule 4: encrypt payloads with a codec, and guard the Codec Server

Per the Temporal data encryption guide (https://docs.temporal.io/production-deployment/data-encryption):

- A Payload Codec encrypts payloads before they reach the Temporal Service, so data is unencrypted only in the client and worker processes. It covers workflow, activity and child workflow inputs and results, signal inputs, memo, headers (check your SDK), query inputs and results, and local activity and side effect results. Failure messages and stack traces are encoded only if you enable that in the Failure Converter.
- A Codec Server is an HTTP server you run (`/encode`, `/decode`, and `/download` for External Storage). It decodes sensitive data in one call, so restrict access. Keeping it on localhost is a pattern the guide accepts. Authorization from the Web UI requires HTTPS, and the Web UI also needs CORS headers.

How this fits with Phantom:

- Running the worker under `phantom exec` keeps provider keys out of it, but it does not deliver a codec key. `phantom exec` exports `phm_` placeholders, and the Phantom proxy injects real credentials only into outbound requests on its routes; it does not hand key material to a process. A codec key stored in Phantom would therefore reach the worker as a placeholder, which cannot encrypt anything. The [codec sketch](../examples/temporal-codec-python/README.md) records the key id in payload metadata for rotation, so key ids land in workflow history and must be plain labels. It prefers to read its keys once from an inherited pipe named by `PHANTOM_TEMPORAL_CODEC_KEYS_FD` (an fd number, not a secret), which keeps them out of argv and the process environment; `PHANTOM_TEMPORAL_CODEC_KEY_<ID>` variables remain as a weaker fallback. Phantom has no command that writes a key to that pipe, so the producer is yours to choose, and it must not take the key on its own command line.
- The sketch's Codec Server binds to `127.0.0.1:8081` and sends no CORS headers by default, which suits the Temporal CLI (`--codec-endpoint`). For the Web UI, list exact origins (scheme, host and port) in `PHANTOM_TEMPORAL_CODEC_CORS_ORIGINS`; `*` and patterns are refused at startup. It then allows only `POST` to `/encode` and `/decode` with `Content-Type` and `X-Namespace`, and refuses a request from any other origin with 403 and no CORS headers. It does not check authorization, so it does not allow the `Authorization` header; leave the UI's codec "pass access token" and "include credentials" settings off. The browser origin is the exact URL you open, so `http://localhost:8233` and `http://127.0.0.1:8233` are different origins. See the local end-to-end check below for what was and was not verified.
- A codec does not make it safe to put a raw secret in a payload (Rule 1).

### Local end-to-end check (2026-10-19, one Linux x86_64 box, fake data only)

Setup:

- Temporal CLI v1.9.1 from the temporalio/cli GitHub release. `sha256sum -c` against the release's `checksums.txt` passed for `temporal_cli_1.9.1_linux_amd64.tar.gz` (sha256 `09a0326a51db84d02735e53542b9ebd8c4758daf47482a9ab0abce15844e60d5`). The release publishes no GitHub artifact attestation, so this checks integrity against the release page, not provenance. `temporal --version` reports Server 1.32.0 and UI 2.54.1. That server is older than the v1.32.1 pin in Rule 3; it was used only for this local experiment.
- Python 3 venv with the example's `requirements.txt` (temporalio 1.34.0, cryptography 50.0.2). Phantom built from `main`.
- A throwaway HOME and project with one fake `OPENAI_API_KEY`, imported by `phantom init` into an encrypted-file vault (fake `PHANTOM_VAULT_PASSPHRASE`; no OS keychain on that box).
- A fake 32-byte codec key, generated per run, held in a shell variable and written only into pipes with the `printf` builtin.

Steps:

```sh
temporal server start-dev --ip 127.0.0.1 --ui-ip 127.0.0.1 \
  --db-filename ./dev.db --ui-codec-endpoint http://127.0.0.1:8081
export PHANTOM_TEMPORAL_CODEC_KEY_ID=e2e-test PHANTOM_TEMPORAL_CODEC_KEYS_FD=3
PHANTOM_TEMPORAL_CODEC_CORS_ORIGINS=http://localhost:8233 \
  python codec_server.py 3< <(printf 'e2e-test=%s\n' "$KEY") &
phantom exec -- python e2e_worker.py OPENAI_API_KEY 3< <(printf 'e2e-test=%s\n' "$KEY") &
python e2e_start.py e2e-greeting-2 fake-e2e-input-MARKER-7f3a 3< <(printf 'e2e-test=%s\n' "$KEY")
temporal workflow show -w e2e-greeting-2 --output json
temporal workflow show -w e2e-greeting-2 --output json --codec-endpoint http://127.0.0.1:8081
```

Observed:

- Every listening socket of the dev server was on 127.0.0.1 (gRPC 7233, UI 8233, metrics and internal ports). A snapshot of open TCP sockets of the server, worker, proxy and codec server showed only loopback peers. Traffic was not captured for the whole run.
- `phantom exec` started its proxy on 127.0.0.1 and the worker reported `OPENAI_API_KEY: placeholder`. The worker got the codec key through fd 3 across `phantom exec`. Nothing in argv or the environment carried it.
- The workflow returned `Hello, fake-e2e-input-MARKER-7f3a`.
- Without the codec, `temporal workflow show` listed 4 payloads (workflow input, activity input, activity result, workflow result), all with encoding `binary/encrypted` and `encryption-key-id` `e2e-test`. None contained the marker. The server's SQLite file did not contain the marker either.
- With `--codec-endpoint`, the same 4 payloads showed as `json/plain` with the input and the result in clear.
- CORS with the allowlist set to `http://localhost:8233`, checked with curl: a preflight for `POST` with `content-type,x-namespace` got 204 with `Access-Control-Allow-Origin: http://localhost:8233`, `Access-Control-Allow-Methods: POST, OPTIONS`, `Access-Control-Allow-Headers: Content-Type, X-Namespace`, `Access-Control-Max-Age: 600`, `Vary: Origin`. Preflights from `http://127.0.0.1:8233` and `http://evil.example`, or one asking for `authorization`, got 403 with no CORS headers. A `POST /decode` from the allowed origin returned the decoded payload with `Access-Control-Allow-Origin`. From another origin it got 403 with an empty body.
- Bug found and fixed: the bundled UI's JavaScript (2.54.1, read from the local server) posts to `<endpoint>/decode?preserveStorageRefs=true` with only `Content-Type` and `X-Namespace` (plus `Authorization` only when "pass access token" is on). The sketch compared the path including the query, so every UI call would have failed (preflight 403, POST 404). It now routes on the path only, and the same curl calls with the query got 204 and 200.
- A payload encrypted under a key the codec server no longer has got an immediate 400 from the codec server. `temporal workflow show` reported `context deadline exceeded` after about 10 seconds rather than that 400.

### Why the CLI shows `context deadline exceeded` when the Codec Server refuses (upstream behavior)

Any refusal from a Codec Server reaches `temporal workflow show` as `context deadline exceeded` after about 10 seconds, whatever the HTTP status or body. Source, at the versions CLI v1.9.1 pins in its [go.mod](https://github.com/temporalio/cli/blob/v1.9.1/go.mod) (Go SDK v1.47.0, api-go v1.63.5):

1. The CLI installs the remote codec as a gRPC client interceptor through the connection's dial options ([cliext/client.go L261-L271](https://github.com/temporalio/cli/blob/v1.9.1/cliext/client.go#L261-L271)).
2. The remote codec turns any response other than 200 into a plain Go error, `"<status text>: <body>"` ([converter/codec.go L397-L414](https://github.com/temporalio/sdk-go/blob/v1.47.0/converter/codec.go#L397-L414)). A 200 whose body cannot be used also returns a plain error (same lines). The interceptor passes that error up unchanged ([proxy/interceptor.go L146-L151](https://github.com/temporalio/api-go/blob/v1.63.5/proxy/interceptor.go#L146-L151)).
3. The SDK chains its own interceptors first, including the gRPC retry interceptor, and appends user dial options after them ([internal/grpc_dialer.go L100](https://github.com/temporalio/sdk-go/blob/v1.47.0/internal/grpc_dialer.go#L100), [L138](https://github.com/temporalio/sdk-go/blob/v1.47.0/internal/grpc_dialer.go#L138), [L162](https://github.com/temporalio/sdk-go/blob/v1.47.0/internal/grpc_dialer.go#L162)). So the codec call runs inside the retry loop.
4. A plain error converts to gRPC code `Unknown`, which the SDK treats as retryable ([internal/common/retry/interceptor.go L108](https://github.com/temporalio/sdk-go/blob/v1.47.0/internal/common/retry/interceptor.go#L108), [L148-L165](https://github.com/temporalio/sdk-go/blob/v1.47.0/internal/common/retry/interceptor.go#L148-L165)).
5. Without `--follow`, the history call runs under the default 10 second RPC timeout ([internal/internal_utils.go L27](https://github.com/temporalio/sdk-go/blob/v1.47.0/internal/internal_utils.go#L27), [internal/internal_workflow_client.go L458](https://github.com/temporalio/sdk-go/blob/v1.47.0/internal/internal_workflow_client.go#L458)). The retries run until that deadline, and the deadline error replaces the codec's message.

Measured on the same box (CLI v1.9.1 dev server on 127.0.0.1, a stub codec that counts requests, one terminated workflow with a fake input): 400 with a text body, 500, 422 with a JSON error body, and 200 with the wrong payload count each produced 5 `/decode` calls and `context deadline exceeded` after 10.0 seconds. No status or body fails fast, so the sketch keeps answering 400, as the SDK's own codec HTTP handler does ([converter/codec.go L297-L333](https://github.com/temporalio/sdk-go/blob/v1.47.0/converter/codec.go#L297-L333)). When you see this error from the CLI, read the Codec Server's own output for the reason. The Temporal guide describes one alternative for callers who are not allowed to decode: return the original encoded payloads with 200. The sketch does not do that, because it would also hide real failures such as an unknown key id.

Not verified: the Web UI rendering decoded payloads in a browser (no browser was driven; only the UI's request shape was checked), Authorization or HTTPS for the Codec Server, External Storage (`/download`), Temporal Cloud, Windows or macOS, and Server v1.32.1 or newer.

## Rule 5: treat inbound text as data

Workflows that react to email, webhooks, or issue text must treat that text as untrusted data. Do not pass it to a model as instructions, and do not let it choose which secrets, tools, or approvals are used. Anything irreversible (send, publish, rotate, delete) needs an explicit approval step that the inbound text cannot supply.

## Where Temporal could help Phantom workflows (DESIGN, untested)

- Rotation: detect, mint, store, verify, revoke, with retries and a human approval signal. History would hold secret names and opaque lease ids only.
- Leases: a durable timer that revokes at expiry even if the issuing process died.
- Leak response: a finding arrives as a signal and is deduplicated by workflow id.

None of these is implemented. Lease and leak-alert designs wait for the lease security review.

## Not covered

No Temporal credential patterns are in the Phantom leak scan yet. Confirm the real formats before adding any. Hosted Temporal Cloud behavior was not tested.
