# Security review draft: a plain-HTTP loopback upstream route

Status: DRAFT for review. Docs only. No proxy or config code is changed by this PR, and none should change until this review is accepted. Written 2026-10-18 from the code on `main`; every claim below names the code it came from. Items marked OPEN were not verified.

## Why this is being considered

The [LiteLLM guide](../litellm.md) runs LiteLLM behind Phantom (LiteLLM to Phantom to provider). The opposite order (agent to Phantom to a local LiteLLM, so Phantom injects a LiteLLM key and agents never hold one) needs a route whose upstream is a plain-HTTP loopback address such as `http://127.0.0.1:4000`. Today that route cannot be expressed. This document lists what such a route would change, so a reviewer can decide whether to allow it and under what rules. It recommends the most restrictive option (see Recommendation) and recommends against building anything broader.

## What the code does today

1. `ServiceRegistry::from_config` builds every route target as `format!("https://{pattern}")` (`crates/phantom-proxy/src/services.rs`, `from_config`). A config-defined route cannot be plain HTTP.
2. `ServiceRoute.target_base` is a public field and `ServiceRegistry::add_route` is public. Plain-HTTP loopback routes already exist in the proxy's own unit tests (for example `target_base: format!("http://127.0.0.1:{}", mock.port)` in `server.rs` tests) and in the LiteLLM test harness. So the proxy engine can forward to `http://`; only the config path forbids it.
3. `phantom exec` and agentic sessions accept only Phantom's exact built-in route definitions. `PhantomConfig::validate_agentic_proxy_routes` and `TRUSTED_PROXY_SERVICES` in `crates/phantom-core/src/config.rs` reject a custom route with "custom proxy service ... is not approved for agentic execution". The doc comment there says custom gateways need "a value-blind, local approval record" that the v1 config format does not have.
4. The upstream client in `ProxyServer::start` (`server.rs`) uses `no_proxy()` and `redirect(Policy::none())`, so an upstream cannot redirect a credential-bearing request elsewhere and an agent-set proxy variable cannot divert it.
5. The proxy injects the real credential into a header chosen by the route (`header`, `header_format`) after matching the route name from the first path segment.

## What a loopback HTTP route would change

| Concern | Why it matters | Proposed rule if allowed |
|---|---|---|
| Plaintext on the wire | Credential-bearing request without TLS | Loopback only, so it never leaves the host. Accept only the literal addresses `127.0.0.1` and `[::1]`, never a hostname (`localhost` resolution, DNS rebinding, and hosts-file changes all alter the destination). Reject every other `http://` target. |
| Any local process can listen on the port | A different local process that binds the port first receives the injected credential | Require an explicit port, fail closed if the port is not listening at start, and document that same-user processes are already inside Phantom's stated threat boundary. Consider a startup check that the listener's owner matches the user (OPEN: not verified, platform specific). |
| Repository-authored config | A cloned repo's `.phantom.toml` could point a route at a local port and receive injected credentials | Do NOT allow this from repository config. Item 3 already blocks custom routes for agentic runs. The approval must live in machine-local state outside the repo, value-blind, with a hash of the exact route definition, as the existing doc comment proposes. |
| Credential injected is a gateway key | The injected value is a LiteLLM key, which can reach every provider LiteLLM is configured for | Scope it as a virtual key with model and budget limits (LiteLLM feature, requires its Postgres; OPEN: not tested here). Never inject the LiteLLM master key. |
| Redirects and proxy variables | Same as today | Keep `no_proxy()` and `Policy::none()`; add a test that a loopback upstream cannot redirect to a non-loopback host. |
| Response handling | A gateway may echo request headers or keys in errors | Run the existing response scrubber on gateway responses; add a test with an echoing mock (OPEN: not written). |
| Surface area of LiteLLM itself | Its proxy has had critical advisories (research note, 2026-10-18: auth bypass, SSRF, RCE, key disclosure) | Doc stays "optional, loopback only, pinned and cosign verified". Phantom must not start or manage LiteLLM. |
| Logging | URLs with the session token can appear in logs | Prefer header authentication for this route (`PHANTOM_PROXY_HEADER_AUTH_ONLY`) so the session token is not in a URL (OPEN: LiteLLM `extra_headers` support not tested). |

## Recommendation

Option B, in its most restrictive form, and only after this review is merged and the maintainer has read it:

- Opt-in only. Off by default. No route exists until the user creates a machine-local, value-blind approval for the exact route definition (hash of the definition, stored outside any repository).
- Loopback addresses only. The literal `127.0.0.1` or `[::1]` with an explicit port. No hostnames (including `localhost`), no `0.0.0.0`, no private ranges, no userinfo in the URL.
- Refuses redirects and any non-loopback host. Keep `Policy::none()` and `no_proxy()`, and fail the request if the target ever resolves to anything other than the approved loopback address and port.
- Never configurable from repository config, never available to agentic runs from repo-authored `.phantom.toml`.
- Inject only a scoped LiteLLM virtual key, never the master key.

Option A stays the default guidance until then. Option C is not recommended now: it generalizes the risk to arbitrary custom routes.

## Options

A. Do nothing. LiteLLM behind Phantom (the guide) already keeps real provider keys out of LiteLLM. Agents hold a LiteLLM key. Lowest risk, already tested against a mock.
B. Add a trusted built-in entry, for example `litellm`, whose pattern allows only `127.0.0.1:<port>` over HTTP, behind an explicit machine-local approval. Needs a code-owner-style review of `config.rs` and the registry; no CODEOWNERS file exists on this repo's main, so the maintainer decision is the gate.
C. Machine-local approval ledger for arbitrary custom routes, the generalization the config doc comment anticipates. Larger design, out of scope here.

## Tests a future change must include

- `from_config` still produces only `https://` for every repository-authored pattern.
- A loopback route is accepted only from the machine-local approval and only for `127.0.0.1` or `[::1]` with a port; `localhost`, `0.0.0.0`, private ranges, userinfo (`http://127.0.0.1@evil`), and non-numeric hosts are rejected.
- A cloned repo config naming a loopback route is refused for agentic runs.
- A loopback upstream answering 302 to an external host is not followed.
- Echoing upstream: injected value never appears in the response returned to the agent.

## Decision requested

Recommended: B (restrictive form above). Choose A, B or C. Until the maintainer has read this review and it is merged, no code is written. This draft was not reviewed by anyone yet.
