---
title: "How AI Coding Tools Leak Your API Keys — And What I Built to Stop It"
published: false
description: "Every AI coding agent can read your .env file. I built an open-source Rust CLI that replaces real secrets with phantom tokens and injects credentials via a local proxy."
tags: security, ai, rust, opensource
cover_image: https://phm.dev/featured-1920x1080.png
canonical_url: https://phm.dev/blog/launch
---

Last week I watched Claude Code read my `.env` file, extract my OpenAI API key, and paste it into a curl command in a shell script it was writing for me. The key worked. The script worked. And my `sk-proj-` key was now sitting in a file on disk, in Claude's session history, and in Anthropic's API logs.

I didn't ask Claude to use the key. It just... did what a helpful agent does. It saw the environment, understood the task, and wired things up. That's the whole point of AI coding tools. It's also the problem.

## The threat is not hypothetical

GitGuardian's 2025 State of Secrets Sprawl report found 39.6 million secrets leaked in public repositories — an 81% year-over-year increase. The number that matters: **AI-assisted commits leak secrets at twice the baseline rate.** The tools that make us most productive are also the most prolific secret-leakers in the history of software development.

Here's why. Every AI coding tool follows the same pattern:

1. You have a `.env` file with `OPENAI_API_KEY=sk-proj-abc123...`
2. The AI agent reads that file to understand your project
3. Your real API key is now inside the LLM's context window

Once a secret enters the context window, every downstream system becomes an attack surface:

- **Session logs.** Most AI tools persist conversation history. Your key is sitting in a JSON file in `~/.claude/` or `~/.cursor/`, probably unencrypted.
- **Prompt injection.** A malicious README, dependency, or code comment can instruct the LLM to exfiltrate environment variables. This isn't theoretical — Check Point Research demonstrated it with CVEs against both Cursor and Claude Code: crafted prompts that trick the agent into sending secrets to attacker-controlled servers.
- **Malicious MCP servers.** The Model Context Protocol lets AI tools call external services. A compromised MCP server can request environment context and receive your real keys.
- **Accidental commits.** The AI writes code that hardcodes a key, or generates a test fixture with real credentials. You review it quickly, approve, and push.

The standard advice — "just don't put secrets in `.env`" — ignores reality. Developers need secrets in their environment to build software. The question isn't whether AI will read your `.env`. It's what it finds when it does.

## Phantom tokens: let the AI read your .env, but make it harmless

I built [Phantom](https://phm.dev) to solve this at the architecture level. The core idea: instead of hiding your `.env` from AI (which defeats the purpose of having an AI agent), replace every real secret with a **phantom token** — a cryptographically random string that looks like an API key but is worthless.

Here's what your `.env` looks like before and after running `phantom init`:

```bash
# Before
OPENAI_API_KEY=sk-proj-abc123def456ghi789...
STRIPE_SECRET_KEY=sk_live_51HG7a9s8d7f6g5h4j3k2l1...
DATABASE_URL=postgresql://admin:s3cret@db.example.com:5432/prod
NODE_ENV=development
PORT=3000

# After
OPENAI_API_KEY=phm_a7f3b9e2d1c4f8a6b3e7d2c5f9a1b4e8...
STRIPE_SECRET_KEY=phm_c3d7f2a9e1b5d8c4a7f3b6e2d9c1a5f8...
DATABASE_URL=phm_e8b2d5a9c3f7e1b4d8a2c6f3e7b1d5a9...
NODE_ENV=development
PORT=3000
```

Those `phm_` tokens are 256-bit CSPRNG values. They parse like API keys. But they are cryptographically worthless. If an AI agent leaks one — into a session log, a commit, a prompt injection payload — nothing happens. Non-secret config values like `NODE_ENV` and `PORT` are detected by heuristics and left untouched.

Your real secrets are stored in the OS keychain (macOS Keychain, Linux Secret Service, or an encrypted file fallback for CI environments).

## The reverse proxy: where phantom tokens become real

When you run `phantom exec -- claude`, Phantom starts a local HTTP reverse proxy on `127.0.0.1` and rewrites the base URLs in your environment:

```bash
OPENAI_BASE_URL=http://127.0.0.1:54321/openai
ANTHROPIC_BASE_URL=http://127.0.0.1:54321/anthropic
STRIPE_API_BASE=http://127.0.0.1:54321/stripe
```

Here's the full request lifecycle:

```
Your code / AI agent
     |
     |  POST http://127.0.0.1:54321/openai/v1/chat/completions
     |  Authorization: Bearer phm_a7f3b9e2...
     v
Phantom Proxy (localhost)
     |
     |  1. Scan headers + body for phm_ tokens
     |  2. Look up real secret from vault
     |  3. Replace: phm_a7f3b9e2... -> sk-proj-abc123...
     |  4. Forward over TLS to api.openai.com
     |  5. Zeroize real secret from memory
     v
OpenAI API (real endpoint, HTTPS)
     |
     |  Response streams back through proxy unchanged
     v
Your code / AI agent
```

This is **not** a MITM proxy. It does not inject CA certificates or break TLS. Your code sends plaintext HTTP to localhost; the proxy initiates a fresh TLS connection to the upstream API. This is a standard reverse proxy pattern — the same architecture as nginx sitting in front of an application server.

Key design decisions:

- **Allowlist model.** The proxy only injects secrets for explicitly configured service patterns. A request to an unknown host receives the phantom token unchanged, which simply fails as an invalid key. Secrets are never sent to unexpected destinations.
- **Localhost only.** The proxy binds to `127.0.0.1`, never `0.0.0.0`. It is not reachable from the network.
- **Ephemeral ports.** Each session gets a random high port, reducing the window for local process abuse.
- **Session-scoped.** When the `exec` session ends, the proxy shuts down. The phantom tokens become inert. There is no running process to resolve them.

Every SDK that supports `BASE_URL` configuration — OpenAI, Anthropic, Stripe, Supabase — works without code changes.

## Real usage: three commands

```bash
# 1. Initialize — detects secrets, stores them safely, rewrites .env
$ npx phantom-secrets init
-> Found .env with 5 entries
-> Detected 3 secret(s): OPENAI_API_KEY, STRIPE_SECRET_KEY, DATABASE_URL
-> Skipped 2 non-secret(s): NODE_ENV, PORT
-> Stored real values in OS keychain
-> Rewrote .env with phantom tokens
ok Project initialized. Run `phantom exec -- <cmd>` to start coding.

# 2. Work with AI — proxy handles everything transparently
$ phantom exec -- claude
-> Proxy listening on 127.0.0.1:54321
-> Injecting: OPENAI_API_KEY, STRIPE_SECRET_KEY, DATABASE_URL
-> Starting: claude

# Claude reads .env, sees phm_ tokens, writes code that calls OpenAI.
# The SDK hits localhost, proxy swaps tokens, forwards to real API.
# Everything works. Claude never touched a real key.

# 3. Deploy — push real secrets to your platform
$ phantom sync --platform vercel
-> Synced 3 secrets to Vercel (real values, not phantom tokens)
```

## MCP server for AI-native secret management

Phantom also ships an MCP server so Claude Code, Cursor, Windsurf, and Codex can manage secrets natively — listing, adding, rotating — without ever seeing a real value:

```bash
$ claude mcp add phantom-secrets-mcp -- npx phantom-secrets-mcp
```

Seventeen tools: `phantom_list_secrets`, `phantom_status`, `phantom_init`, `phantom_add_secret`, `phantom_remove_secret`, `phantom_rotate`, `phantom_copy_secret`, `phantom_cloud_push`, `phantom_cloud_pull`, `phantom_cloud_status`.

## Architecture: 5-crate Rust workspace

```
phantom-core     Config, .env parsing, token generation (256-bit CSPRNG, phm_ prefix)
phantom-vault    VaultBackend trait: OS keychain + encrypted file fallback
phantom-proxy    HTTP reverse proxy (hyper), token replacement, TLS forwarding (reqwest)
phantom-cli      clap-based CLI, 27 commands
phantom-mcp      MCP server (rmcp SDK), stdio transport, 17 tools
```

The vault uses ChaCha20-Poly1305 for encryption with Argon2id key derivation (for the encrypted file fallback). The `zeroize` crate scrubs secrets from memory after every proxy injection. 69 tests, zero clippy warnings.

Cloud sync is available for backing up vaults across machines — end-to-end encrypted, zero-knowledge. The server at phm.dev stores only ciphertext.

## Why not existing tools?

I looked at the landscape before building this.

**1Password / HashiCorp Vault** — Enterprise-grade secret management. But `op run` and similar injection patterns put the real secret into the environment. If the AI agent reads it, the real key enters the context window. No proxy pattern, no phantom tokens.

**Doppler / Infisical** — Good centralized secret management, but focused on deployment pipelines. At runtime, secrets are injected as real environment variables. The AI reads them.

**dotenvx** — Encrypts `.env` files at rest, which is useful. But at runtime, secrets are decrypted into real environment variables. The AI sees them.

The gap: existing tools protect secrets between humans and servers. None of them address the AI agent in the middle — the one that reads your `.env`, holds secrets in a context window, and can be manipulated into leaking them.

## Get started

```bash
npx phantom-secrets init
```

Three commands. Ten seconds. Your AI tools use your real API keys without ever seeing them.

Phantom is open-source (MIT), written in Rust, free for individuals, and has no SaaS dependency. The CLI and proxy will always be free.

- **Website**: [phm.dev](https://phm.dev)
- **GitHub**: [github.com/ashlrai/phantom-secrets](https://github.com/ashlrai/phantom-secrets)
- **Docs**: [phm.dev/docs/getting-started](https://phm.dev/docs/getting-started)

If you've ever pasted an API key into an AI coding tool and felt a twinge of guilt — you were right to. But you don't have to stop using AI to fix it.
