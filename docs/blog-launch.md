# How AI coding tools leak your API keys — and what I built to stop it

Last week I watched Claude Code read my `.env` file, extract my OpenAI API key, and paste it into a curl command in a shell script it was writing for me. The key worked. The script worked. And my `sk-proj-` key was now sitting in a file on disk, in Claude's session history, and in Anthropic's API logs.

I didn't ask Claude to use the key. It just... did what a helpful agent does. It saw the environment, understood the task, and wired things up. That's the whole point of AI coding tools. It's also the problem.

## The threat is not hypothetical

GitGuardian's [State of Secrets Sprawl 2026](https://blog.gitguardian.com/the-state-of-secrets-sprawl-2026/)
reports 28.65 million new hardcoded secrets in public GitHub commits in 2025, a
34% year-over-year increase. AI-service secrets separately increased 81% year
over year; that category-specific figure does not apply to all secrets.

Here is one common high-risk pattern when an AI coding tool has dotenv access:

1. You have a `.env` file with `OPENAI_API_KEY=sk-proj-abc123...`
2. The AI agent reads that file to understand your project
3. Your real API key is now inside the LLM's context window

Once a secret enters the context window, several downstream systems can become exposure paths:

- **Session logs.** Most AI tools persist conversation history. Your key is sitting in a JSON file in `~/.claude/` or `~/.cursor/`, probably unencrypted.
- **Prompt injection.** A malicious README, dependency, or code comment can instruct the LLM to exfiltrate environment variables. This isn't theoretical — Check Point Research demonstrated it with CVEs against both Cursor and Claude Code: crafted prompts that trick the agent into sending secrets to attacker-controlled servers.
- **Malicious MCP servers.** The Model Context Protocol lets AI tools call external services. A compromised MCP server can request environment context and receive your real keys.
- **Accidental commits.** The AI writes code that hardcodes a key, or generates a test fixture with real credentials. You review it quickly, approve, and push.

The standard advice — "just don't put secrets in `.env`" — ignores reality. Developers need secrets in their environment to build software. The question isn't whether AI will read your `.env`. It's what it finds when it does.

## Phantom tokens: keep real credentials out of the AI boundary

I built [Phantom](https://phm.dev) to reduce that exposure at the architecture
level. The core idea: replace heuristically detected, Phantom-managed dotenv
secrets with **phantom tokens** — cryptographically random placeholders that
are not accepted as credentials by the upstream provider.

Here's what your `.env` looks like before and after running `phantom init`:

```
# Before
OPENAI_API_KEY=sk-proj-abc123def456ghi789...
STRIPE_SECRET_KEY=sk_live_51HG7a9s8d7f6g5h4j3k2l1...
ANTHROPIC_API_KEY=sk-ant-api03-example...
NODE_ENV=development
PORT=3000

# After
OPENAI_API_KEY=phm_a7f3b9e2d1c4f8a6b3e7d2c5f9a1b4e8...
STRIPE_SECRET_KEY=phm_c3d7f2a9e1b5d8c4a7f3b6e2d9c1a5f8...
ANTHROPIC_API_KEY=phm_e8b2d5a9c3f7e1b4d8a2c6f3e7b1d5a9...
NODE_ENV=development
PORT=3000
```

Those `phm_` tokens use 256 bits of CSPRNG output. They are not provider
credentials and cannot be redeemed directly against OpenAI, Anthropic, or
Stripe. They are still mappings worth protecting. Client headers and bodies
never resolve them, but a stolen live proxy bearer can authorize exact routes
that inject their own credentials. Rotate an exposed project token. Non-secret config values such as `NODE_ENV` and `PORT`
are normally left untouched by the detection heuristics.

Your real secrets are stored in the OS keychain (macOS Keychain, Linux Secret Service, or an encrypted file fallback for CI environments).

The real question: if the `.env` has fake keys, how does anything actually work?

## The reverse proxy: route-owned authentication

When you run `phantom exec -- claude`, Phantom starts a local HTTP reverse proxy on `127.0.0.1` and rewrites the base URLs in your environment:

```
OPENAI_BASE_URL=http://127.0.0.1:PORT/openai
ANTHROPIC_BASE_URL=http://127.0.0.1:PORT/anthropic
STRIPE_API_BASE=http://127.0.0.1:PORT/stripe
```

Here's the request lifecycle:

```
Your code / AI agent
     |
     |  POST http://127.0.0.1:PORT/openai/v1/chat/completions
     |  Client request (no credential substitution)
     v
Phantom Proxy (localhost)
     |
     |  1. Authenticate session and match exact route
     |  2. Inject route-owned key into fixed auth header
     |  3. Forward client headers/body without token resolution
     |  4. Forward over TLS to api.openai.com
     |  5. Drop request buffers; the session lookup copy remains until proxy exit
     v
OpenAI API (real endpoint, HTTPS)
     |
     |  Response returns through content-aware scrubbing
     v
Your code / AI agent
```

This is not a MITM proxy. It does not inject CA certificates or break TLS. Your code sends plaintext HTTP to localhost; the proxy initiates a fresh TLS connection to the upstream API. This is a standard reverse proxy pattern — the same architecture as nginx sitting in front of an application server.

The key design decisions:

- **Reviewed routes.** Agentic proxy sessions accept Phantom's exact built-in service definitions and reject repository-authored proxy destinations. This constrains injection, but endpoint integrity, DNS/TLS, the local account, and the configured provider remain in the threat model.
- **Localhost only.** The proxy binds to `127.0.0.1`, never `0.0.0.0`. It is not reachable from the network.
- **Ephemeral ports.** Each session gets a random high port, reducing the window for local process abuse.
- **Session-scoped proxy authentication.** `phantom exec` gives the child process fresh `phm_` placeholders and a fresh proxy bearer. Client placeholders never resolve; the bearer becomes invalid when that proxy exits. Project tokens stored in dotenv are different values and persist until `phantom rotate`.

Supported SDKs that honor Phantom's implemented base-URL overrides can work
without source changes. This is not a claim for every HTTP client or protocol.
Protected database connection strings currently make `phantom exec` fail
closed; Phantom does not inject them into the child environment.

## Real usage: three commands

```bash
# 1. After installing the reviewed v0.7.3 release, initialize the project
$ phantom init
-> Found .env with 5 entries
-> Detected 3 secret(s): OPENAI_API_KEY, STRIPE_SECRET_KEY, ANTHROPIC_API_KEY
-> Skipped 2 non-secret(s): NODE_ENV, PORT
-> Stored real values in OS keychain
-> Rewrote .env with phantom tokens
ok Project initialized. Run `phantom exec -- <cmd>` to start coding.

# 2. Work with AI — supported SDK routes use the proxy
$ phantom exec -- claude
-> Proxy listening on an ephemeral 127.0.0.1 port
-> Proxying: OPENAI_API_KEY, STRIPE_SECRET_KEY, ANTHROPIC_API_KEY
-> Starting: claude

# The app loads phm_ tokens; Claude uses value-blind MCP metadata.
# The SDK hits localhost; the matched route injects its fixed auth header and forwards to the real API.
# Supported SDK calls use the reviewed local proxy route; MCP stays value-blind.

# 3. Deploy — push real secrets to your platform
$ phantom sync --platform vercel
-> Synced 3 secrets to Vercel (real values, not phantom tokens)
```

Phantom also ships an MCP server so Claude Code, Cursor, Windsurf, and Codex can manage secrets natively — listing, adding, rotating — without ever seeing a real value:

```bash
$ phantom setup --client claude
```

The release-schema-verified catalog currently contains 54 unique tools covering
vault status, init, safe interactive secret entry, checks, diagnostics, cloud
sync, audit, validation, rotation, expiry, compliance, and team vaults. The
deprecated plaintext add tool refuses secret values through MCP, so real
credentials stay out of the agent context. Runtime `tools/list` is canonical.

## Architecture

Phantom is a modular Rust workspace:

```
phantom-core     Config, .env parsing, token generation (256-bit CSPRNG, phm_ prefix)
phantom-vault    VaultBackend trait: OS keychain + encrypted file fallback
phantom-proxy    HTTP reverse proxy (hyper), token replacement, TLS forwarding (reqwest)
phantom-cli      clap-based CLI with agent readiness, proxy, sync, audit, teams
phantom-mcp      MCP server (rmcp SDK), stdio transport, schema-verified catalog
workspace/kernel Value-blind setup plus fail-closed governed-execution foundations
```

The vault uses ChaCha20-Poly1305 for encryption with Argon2id key derivation
(for the encrypted file fallback). Major vault retrieval, serialization, and
decrypted-file buffers use targeted zeroization, while some proxy lookup copies
remain ordinary strings. Zeroization is defense in depth, not a complete
memory-erasure guarantee. CI runs the Rust test suite and clippy before release.

The cloud client can encrypt a vault payload before upload so the vault API
stores ciphertext rather than decrypted secret values. That property does not
remove the client, account, endpoint, or deployed-service trust boundaries.

## Why not existing tools?

I looked at the landscape before building this.

**1Password / HashiCorp Vault** — Enterprise secret-management systems with
different runtime models. Environment-injection workflows such as `op run` can
still expose a value to an agent that can inspect that process environment;
their current product capabilities should be evaluated independently.

**Doppler / Infisical** — Centralized secret-management systems that can inject
real values at runtime. If an agent can inspect the target environment, that
specific integration pattern may cross the agent context boundary.

**dotenvx** — Encrypts `.env` files at rest, which is useful. But at runtime, secrets are decrypted into real environment variables. The AI sees them.

The design gap Phantom targets is narrower: agent workflows where readable
dotenv values or real process-environment credentials can enter model context,
transcripts, generated files, or tool calls.

## Get started

```bash
phantom init
```

Install the checksum-verified `v0.7.3` binaries using the
[current platform instructions](./getting-started.md#install) before running
this command. Three commands establish the local boundary for supported API routes. Keep
dotenv reads denied, review the generated config, and use the documented
recovery and CI controls for the rest of the system.

Phantom's local CLI and proxy are MIT-licensed Rust software and do not require
the hosted service for local protection. Hosted packaging and future pricing
are separate from the open-source license.

- **Website**: [phm.dev](https://phm.dev)
- **GitHub**: [github.com/ashlrai/phantom-secrets](https://github.com/ashlrai/phantom-secrets)
- **Docs**: [phm.dev/docs/getting-started](https://phm.dev/docs/getting-started)

If you've ever pasted an API key into an AI coding tool and felt a twinge of guilt — you were right to. But you don't have to stop using AI to fix it.
