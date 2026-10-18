# LiteLLM as an optional gateway behind Phantom

Status: experimental. Read "What was tested" before relying on any of this.

[LiteLLM](https://github.com/BerriAI/litellm) is a separate, optional Python service that exposes many model providers behind one OpenAI-style endpoint. Phantom does not depend on it and does not ship it. This page shows how to run LiteLLM so that it never holds a real provider key: LiteLLM sends a `phm_` placeholder, and Phantom's local proxy injects the real key.

Phantom answers "who holds the real key". LiteLLM answers "which model and which budget". They are complementary. Without Phantom, LiteLLM reads real keys from its config, environment, or database, and that is exactly what a compromised LiteLLM process steals.

## Pin and verify LiteLLM first

- PyPI releases `litellm==1.82.7` and `1.82.8` were malicious. LiteLLM states they were live on 2026-03-24 from 10:39 UTC for about 40 minutes and have been removed from PyPI. They harvested environment variables, SSH keys and cloud credentials. Source: https://docs.litellm.ai/blog/security-update-march-2026 (checked 2026-10-18).
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
- Set `allow_client_side_credentials: false` under `general_settings`. LiteLLM documents this as the workaround for GHSA-3cv6-jpf6-8222, where a caller could redirect the proxy's outbound call and make it send its provider credentials to another host.
- No Enterprise features. Do not set `LITELLM_LICENSE`. Installing the `proxy` extra also installs a `litellm-enterprise` package; I did not verify what it enables, and this setup configures no Enterprise feature.
- Same-user processes on your machine can still reach Phantom's loopback proxy and see its session token. Phantom's threat model says so, and running LiteLLM does not change it.

## Setup

1. Add the provider to Phantom as usual so `phantom exec` exports `OPENAI_API_KEY` as a `phm_` placeholder and `OPENAI_BASE_URL` as the local proxy URL (`http://127.0.0.1:<port>/openai/_phantom/<session token>/`).
2. Use [`examples/litellm/config.yaml`](../examples/litellm/config.yaml). It reads `api_base` and `api_key` from those variables and sets `allow_client_side_credentials: false`.
3. Start LiteLLM under Phantom, bound to loopback, with a master key that only the LiteLLM process and your agents know:

```bash
LITELLM_MASTER_KEY=sk-<your own random value> \
  phantom exec -- litellm --config examples/litellm/config.yaml --host 127.0.0.1 --port 4000
```

4. Point an agent at `http://127.0.0.1:4000` with the LiteLLM master key (or a virtual key) as its credential. Never give an agent a provider key or the Phantom proxy token.

Per-agent setup lives in [Claude Code](claude-code.md), [Codex](codex.md) and [Cursor](cursor.md) under "Gateway mode".

## What was tested

Run on 2026-10-18 with `examples/litellm/verify.py` (`LITELLM_BIN=<path to litellm> python3 examples/litellm/verify.py`):

- LiteLLM 1.103.5 installed from PyPI wheels into a fresh virtualenv, started with a cleared environment and a temporary HOME.
- The real Phantom proxy code, started by a test harness (`crates/phantom-proxy/examples/litellm_loopback_harness.rs`) with an `openai` route whose upstream is a plain-HTTP mock on 127.0.0.1. The harness is needed because routes built from `.phantom.toml` are always `https://`, so a mock upstream cannot be reached through the CLI path. It copies the `phantom exec` proxy settings (session token in the URL path, `/v1` added for the OpenAI route).
- One non-streaming `POST /v1/chat/completions` through LiteLLM. The mock recorded the request. Checks that passed: the mock received the injected stand-in credential in `Authorization`; it never saw the `phm_` placeholder, the LiteLLM master key, or the Phantom session token; the request path reached the mock as `/v1/chat/completions`; the LiteLLM log at default verbosity and the LiteLLM environment never contained the stand-in real credential.

Not tested: any real provider, streaming, tool calls, the `phantom exec` CLI end to end, the Docker image, Postgres or virtual keys, LiteLLM debug logging (it may print `api_base`, which contains the Phantom session token), the Responses API, and Claude Code, Codex, Gemini CLI or Cursor talking to LiteLLM.

## Not supported

- Cursor: LiteLLM's own docs say the IDE integration needs a URL reachable from the internet, which conflicts with loopback only. Cursor's CLI is not supported by LiteLLM. Do not expose a keyholding proxy for Cursor.
- Phantom in front of LiteLLM (agent to Phantom to LiteLLM) needs a plain-HTTP loopback upstream route, which Phantom does not allow today. See the security review draft before any such change.
