# LiteLLM as an optional gateway behind Phantom

Status: experimental. Read "What was tested" before relying on any of this.

[LiteLLM](https://github.com/BerriAI/litellm) is a separate, optional Python service that exposes many model providers behind one OpenAI-style endpoint. Phantom does not depend on it and does not ship it. This page shows how to run LiteLLM so that it never holds a real provider key: LiteLLM sends a `phm_` placeholder, and Phantom's local proxy injects the real key.

Phantom answers "who holds the real key". LiteLLM answers "which model and which budget". They are complementary. Without Phantom, LiteLLM reads real keys from its config, environment, or database, and that is exactly what a compromised LiteLLM process steals.

## Pin and verify LiteLLM first

- PyPI releases `litellm==1.82.7` and `1.82.8` were malicious. LiteLLM states they were live on 2026-03-24 from 10:39 UTC for about 40 minutes and have been removed from PyPI. They harvested environment variables, SSH keys and cloud credentials. Source: https://docs.litellm.ai/blog/security-update-march-2026 (checked 2026-10-18). GitHub advisory GHSA-5mg7-485q-xm76 (critical) covers `>=1.82.7, <=1.82.8`: https://github.com/advisories/GHSA-5mg7-485q-xm76.
- LiteLLM's same post says the official proxy Docker image was not affected, because it pins its dependencies.
- LiteLLM resumed releases at `v1.83.0` from a rebuilt pipeline. Use `1.83.0` or newer, and re-check the advisory list for the version you pick, because the proxy has had serious advisories since (https://github.com/BerriAI/litellm/security-advisories). The example below was run with `1.103.5`.
- Never run an unpinned `pip install litellm` on a machine that holds real secrets.
- Preferred: the official image, verified with cosign. LiteLLM signs images from `v1.83.0-nightly` onward with one key introduced in commit `0112e53`:

```bash
cosign verify \
  --key https://raw.githubusercontent.com/BerriAI/litellm/0112e53046018d726492c814b3644b7d376029d0/cosign.pub \
  ghcr.io/berriai/litellm:<release-tag>
```

- Alternative: a hash-pinned install (`pip install --require-hashes -r requirements.txt` with every transitive dependency hashed, wheels only) in a throwaway virtualenv, started with a minimal environment.

## Rules for this setup

- Optional service only. Phantom and your project must work without it.
- Loopback only: start it with `--host 127.0.0.1`. Do not publish the port.
- Keep real provider keys out of LiteLLM entirely. Do not use `.env` files, `os.environ/` with a real key, or LiteLLM's secret-manager integrations.
- Never use `phantom reveal` to hand a key to LiteLLM (or to anything else in this setup). It prints the real value, which puts it in LiteLLM's environment, your shell history or the clipboard, and undoes the point of the gateway. LiteLLM needs only the `phm_` placeholder that `phantom exec` exports.
- Set `allow_client_side_credentials: false` under `general_settings`. LiteLLM documents this as the workaround for GHSA-3cv6-jpf6-8222, where a caller could redirect the proxy's outbound call and make it send its provider credentials to another host.
- No Enterprise features. Do not set `LITELLM_LICENSE`. Installing the `proxy` extra also installs a `litellm-enterprise` package; I did not verify what it enables, and this setup configures no Enterprise feature.
- Same-user processes on your machine can still reach Phantom's loopback proxy and see its session token. Phantom's threat model says so, and running LiteLLM does not change it.

## Setup

1. Store the provider key in Phantom once, from a trusted terminal (hidden prompt). Your project's `.env` then holds a `phm_` placeholder, not the key:

```bash
phantom add OPENAI_API_KEY
```

2. Under `phantom exec`, the child process gets `OPENAI_API_KEY` as a session `phm_` placeholder and `OPENAI_BASE_URL` as the local proxy URL (`http://127.0.0.1:<port>/openai/_phantom/<session token>/`). LiteLLM reads both from the environment. This is [`examples/litellm/config.yaml`](../examples/litellm/config.yaml):

```yaml
model_list:
  - model_name: gpt-gateway
    litellm_params:
      model: openai/gpt-4o-mini
      api_base: os.environ/OPENAI_BASE_URL   # the Phantom proxy, set by phantom exec
      api_key: os.environ/OPENAI_API_KEY     # a phm_ placeholder, never a real key

general_settings:
  master_key: os.environ/LITELLM_MASTER_KEY
  allow_client_side_credentials: false
```

3. Start LiteLLM under Phantom, bound to loopback, with a master key that only the LiteLLM process and your agents know:

```bash
LITELLM_MASTER_KEY=sk-<your own random value> \
  phantom exec -- litellm --config examples/litellm/config.yaml --host 127.0.0.1 --port 4000
```

4. Point an agent at `http://127.0.0.1:4000` with the LiteLLM master key (or a virtual key) as its credential. Never give an agent a provider key or the Phantom proxy token. See "Connect an agent" below.

## Connect an agent

The agent talks to LiteLLM, and LiteLLM talks to Phantom's proxy with a `phm_` placeholder. In every case the agent's credential is a LiteLLM key, never a provider key or the Phantom proxy token, and LiteLLM stays on `127.0.0.1`. Without the gateway nothing changes: each agent's direct Phantom setup stays the default.

The agent-side settings below come from LiteLLM's documentation. Phantom has not tested any of these agents against LiteLLM; the Phantom side was tested only with OpenAI-style chat completions (see "What was tested").

- **Claude Code**: set `ANTHROPIC_BASE_URL` to the LiteLLM proxy and `ANTHROPIC_AUTH_TOKEN` to a LiteLLM key (https://docs.litellm.ai/docs/tutorials/claude_responses_api). Direct setup: [Claude Code](claude-code.md).
- **Codex**: a custom provider in `~/.codex/config.toml` with `base_url` set to the LiteLLM proxy, `env_key = "LITELLM_API_KEY"` and `wire_api = "responses"` (https://docs.litellm.ai/docs/tutorials/openai_codex). Put a LiteLLM key in `LITELLM_API_KEY`. The Responses API path was not tested. Direct setup: [Codex](codex.md).
- **Gemini CLI**: set `GOOGLE_GEMINI_BASE_URL` to the LiteLLM proxy and `GEMINI_API_KEY` to a LiteLLM key (https://docs.litellm.ai/docs/tutorials/litellm_gemini_cli).
- **Cursor**: not supported with a loopback gateway. LiteLLM's documentation says its Cursor integration (an overridden OpenAI base URL) makes Cursor's servers call the proxy, so it must be reachable from the internet, and calls it best effort (https://docs.litellm.ai/docs/tutorials/cursor_integration). Do not expose a keyholding proxy for Cursor. Direct setup: [Cursor](cursor.md).

## What was tested

Manual smoke test with a real LiteLLM, run on 2026-10-18 with `examples/litellm/verify.py` (`LITELLM_BIN=<path to litellm> python3 examples/litellm/verify.py`):

- LiteLLM 1.103.5 installed from PyPI wheels into a fresh virtualenv, started with a cleared environment and a temporary HOME.
- The real Phantom proxy code, started by a test harness (`crates/phantom-proxy/examples/litellm_loopback_harness.rs`) with an `openai` route whose upstream is a plain-HTTP mock on 127.0.0.1. The harness is needed because routes built from `.phantom.toml` are always `https://`, so a mock upstream cannot be reached through the CLI path. It copies the `phantom exec` proxy settings (session token in the URL path, `/v1` added for the OpenAI route).
- One non-streaming `POST /v1/chat/completions` through LiteLLM. The mock recorded the request. Checks that passed: the mock received the injected stand-in credential in `Authorization`; it never saw the `phm_` placeholder, the LiteLLM master key, or the Phantom session token; the request path reached the mock as `/v1/chat/completions`; the LiteLLM log at default verbosity and the LiteLLM environment never contained the stand-in real credential.

In CI, on every change: `crates/phantom-proxy/tests/litellm_gateway_hermetic_test.rs` (`cargo test -p phantom-secrets-proxy --test litellm_gateway_hermetic_test`). It needs no LiteLLM and no network beyond 127.0.0.1. The test plays the LiteLLM client with only the `phm_` placeholder and the `phantom exec` base URL, against the real proxy built the way `phantom exec` builds it, with a mock OpenAI-compatible upstream and a second mock that no route names. It checks that:

- the placeholder becomes the real key only at the proxy, only in the configured `Authorization` header, and only toward the configured upstream; a placeholder copied into the request body is passed through, never resolved;
- the second mock receives nothing when the client sets a foreign `Host` header, sends an absolute-form URL, adds `X-Forwarded-Host`, `Forwarded` or `X-Original-URL`, or when the upstream answers with a redirect to it (the proxy returns the 307 and does not follow it);
- proxy error bodies (wrong or missing proxy token, unknown route) and upstream bodies that reflect the key (a 401 error and an SSE event) reach the client without it;
- the key is absent from every proxy log line (TRACE level plus stderr) and from the audit ledger (`PHANTOM_AUDIT=1`), which does record the intercepted reflections as `proxy.response_leak`.

Not tested: any real provider, streaming, tool calls, the `phantom exec` CLI end to end, the Docker image, Postgres or virtual keys, LiteLLM debug logging (it may print `api_base`, which contains the Phantom session token), the Responses API, and Claude Code, Codex, Gemini CLI or Cursor talking to LiteLLM.

## LiteLLM as an upstream: key headers

This section covers the other direction: a Phantom route whose upstream is a LiteLLM proxy reached over HTTPS, with the LiteLLM virtual key in the vault and only its `phm_` placeholder in the client.

LiteLLM's docs (checked 2026-10-19) name these headers as places its proxy reads a key from:

- [Gateway Auth Reference](https://docs.litellm.ai/docs/auth_overview), "Client to LiteLLM": "`x-litellm-api-key: Bearer sk-...` | Preferred LiteLLM Virtual Key header", "`Authorization: Bearer sk-...` | Standard fallback. Stripped of the `Bearer ` prefix before lookup.", and "`API-Key`, `x-api-key`, `x-goog-api-key`, `Ocp-Apim-Subscription-Key` | Vendor-specific aliases (Azure, Anthropic, Google AI Studio, Azure APIM)." The same page notes that LiteLLM's MCP routes do not parse the vendor aliases.
- [Virtual Keys](https://docs.litellm.ai/docs/proxy/virtual_keys), "Pass LiteLLM Key in custom header": "Use this to make LiteLLM proxy look for the virtual key in a custom header instead of the default `"Authorization"` header", set with `general_settings: litellm_key_header_name: "X-Litellm-Key"` and sent as `X-Litellm-Key: Bearer $LITELLM_API_KEY`.
- [config.yaml settings](https://docs.litellm.ai/docs/proxy/config_settings): "litellm_key_header_name | str | null (reads Authorization) | If set, allows passing LiteLLM keys as a custom header."

A route sets one of these with `header` and `header_format` in `.phantom.toml`. Use `Bearer {secret}` for `x-litellm-api-key`, `Authorization` and a `litellm_key_header_name` header, as the docs show. The docs show no value format for the vendor aliases; the test uses the bare key (`{secret}`), which is an assumption, not a documented LiteLLM format.

```toml
[services.litellm]
secret_key = "LITELLM_API_KEY"
secret_type = "api_key"
pattern = "litellm.example.internal"
header = "x-litellm-api-key"
header_format = "Bearer {secret}"
```

For such a route the proxy removes the client's copy of that header, injects the real key in its place, and forwards nothing else it owns. Any echo of the key in the response is scrubbed by value, whatever header or body field LiteLLM puts it in.

Limits:

- `phantom exec` refuses this route and runs only Phantom's exact built-in routes; a self-hosted LiteLLM has no fixed host, so it cannot be one. `phantom start` serves it from `.phantom.toml`. Why the difference: `phantom start` is run by a person on project config they have reviewed. `phantom exec` launches an agent, and anything in the repository, `.phantom.toml` included, may have been written by that agent or by an untrusted change, so accepting custom routes there would widen the attack surface. A test pins exec's refusal (`custom_litellm_route_is_refused_by_exec_but_built_for_start` in `crates/phantom-cli/src/commands/exec.rs`).
- The route is always `https://`. A LiteLLM on plain HTTP loopback is not supported (see "Not supported").
- Only the one configured header is swapped. A `phm_` placeholder the client puts in a different header is forwarded as is. LiteLLM then rejects a placeholder, not a real key.

Tested in CI by `crates/phantom-proxy/tests/litellm_upstream_headers_test.rs` (`cargo test -p phantom-secrets-proxy --test litellm_upstream_headers_test`). For each of the seven headers above it builds the route from a `.phantom.toml`-style service, points it at a plain-HTTP mock on 127.0.0.1, and checks that the mock gets the real key exactly once in that header, never sees the placeholder or the proxy token, and that echoes of the key (whole or its last half, in a response header and a JSON body) do not reach the client. A second test does the same for a streamed (`text/event-stream`, chunked) response that echoes the key split across chunks, then its last half, and checks that the stream still completes with `data: [DONE]`. Not tested: a real LiteLLM and `phantom start` end to end.

## Not supported

- Cursor with a loopback gateway (see "Connect an agent"). Cursor's CLI is not supported by LiteLLM.
- Phantom in front of LiteLLM (agent to Phantom to LiteLLM) needs a plain-HTTP loopback upstream route, which Phantom does not allow today. See the security review draft before any such change.
