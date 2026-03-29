---
title: "How to let AI code with your real API keys (without leaking them)"
published: true
tags: security, ai, webdev, tutorial
cover_image: https://phm.dev/og-image.png
---

You want Claude Code to integrate Stripe. You want Cursor to build an OpenAI-powered feature. You want Copilot to wire up your Supabase auth flow. All of these require your real API keys, sitting in `.env`, readable by the AI agent. So you paste them in and hope for the best.

The numbers say that hope is misplaced. GitGuardian's 2025 report found 39.6 million secrets leaked on GitHub in a single year. Worse: AI-assisted commits leak secrets at **twice the baseline rate**. Every time an AI agent reads your `.env`, your real key enters an LLM context window where it can be exfiltrated by prompt injection, logged to a session file, or sent to a malicious MCP server. The tools that make us fastest are also the biggest secret-leaking risk in our workflow.

## The fix: phantom tokens

[Phantom](https://phm.dev) takes a simple approach. Instead of trying to hide your `.env` from AI (which defeats the purpose), it replaces every real secret with a **phantom token** -- a cryptographically random `phm_` prefixed string that looks like an API key but is completely worthless. Your real secrets get stored in your OS keychain.

When your code (or the AI's code) makes an API call, a local reverse proxy intercepts the request, swaps the phantom token for the real credential, and forwards it over TLS to the actual API. The AI never sees the real key. If a phantom token leaks -- into a commit, a session log, a prompt injection payload -- nothing happens. It's not a real credential. It resolves to nothing outside the proxy session.

## Tutorial: protect your project in 60 seconds

Let's walk through the full workflow. Say you have a Next.js project with a `.env` file like this:

```
OPENAI_API_KEY=sk-proj-abc123def456ghi789...
STRIPE_SECRET_KEY=sk_live_51HG7a9s8d7f6g5h4j3k2l1...
DATABASE_URL=postgresql://admin:s3cret@db.example.com:5432/prod
```

### Step 1: Initialize Phantom

```bash
npx phantom-secrets init
```

Output:

```
Found 3 secret(s) to protect: OPENAI_API_KEY, STRIPE_SECRET_KEY, DATABASE_URL
Rewrote .env with phantom tokens
Saved real secrets to OS keychain
```

Your `.env` now looks like this:

```
OPENAI_API_KEY=phm_a7f3b9e2d1c4f8a6b3e7d2c5f9a1b4e8...
STRIPE_SECRET_KEY=phm_c3d7f2a9e1b5d8c4a7f3b6e2d9c1a5f8...
DATABASE_URL=phm_e8b2d5a9c3f7e1b4d8a2c6f3e7b1d5a9...
```

Those `phm_` values are 256-bit CSPRNG tokens. They parse like API keys but carry zero real access. Non-secret values like `NODE_ENV` and `PORT` are left untouched.

### Step 2: Configure your AI tool

```bash
phantom setup
```

This configures Claude Code's MCP integration and pre-commit hooks. Claude can now list and manage your secrets through the MCP server without ever seeing a real value.

### Step 3: Code with AI

```bash
phantom exec -- claude
```

Output:

```
Proxy running on 127.0.0.1:54321
Claude Code sees phantom tokens, proxy injects real keys at network layer
```

Here is what happens under the hood:

| Layer | What it sees |
|-------|-------------|
| Your `.env` file | `OPENAI_API_KEY=phm_a7f3b9e2...` |
| Claude Code context window | `phm_a7f3b9e2...` (safe to leak) |
| HTTP request from your code | `Authorization: Bearer phm_a7f3b9e2...` |
| Phantom proxy (localhost) | Replaces `phm_a7f3b9e2...` with `sk-proj-abc123...` |
| OpenAI API receives | `Authorization: Bearer sk-proj-abc123...` (real key, over TLS) |

Claude writes code that calls the OpenAI SDK. The SDK reads `OPENAI_BASE_URL` (which Phantom sets to `http://127.0.0.1:54321/openai`) and sends the request to the local proxy. The proxy swaps the phantom token, forwards to `api.openai.com`, and your call works. Claude never touched a real key.

When you end the session, the proxy shuts down. The phantom tokens become inert -- there is no running proxy to resolve them. They are session-scoped by design.

## Deploy to Vercel

When it's time to deploy, your CI environment needs real secrets, not phantom tokens. One command handles it:

```bash
phantom sync --platform vercel
```

```
Synced 3 secrets to Vercel (real values, not phantom tokens)
```

Phantom reads real secrets from your vault, pushes them directly to Vercel's environment variables. You can also pull secrets from a platform into your local vault with `phantom pull --platform vercel`.

## How it works under the hood

Three components make this work:

**The vault.** Real secrets are stored in your OS keychain (macOS Keychain with Secure Enclave on Apple Silicon, Linux Secret Service, or an encrypted file fallback for CI). They never exist as plaintext in your project directory after initialization.

**The reverse proxy.** A local HTTP proxy binds to `127.0.0.1` on an ephemeral port. It is not a MITM proxy and does not manipulate TLS certificates. Your code talks plaintext to localhost; the proxy initiates a fresh TLS connection to the upstream API. It uses an allowlist model -- only configured service patterns get real secrets injected. A request to an unknown host receives the phantom token unchanged, which simply fails as an invalid key.

**Memory safety.** After injecting a real secret into an outgoing request, Phantom zeroizes it from memory using the `zeroize` crate. The encryption layer uses ChaCha20-Poly1305 with Argon2id key derivation for the file-based vault fallback.

## Other useful commands

```bash
phantom status          # See what's protected and proxy state
phantom add KEY VALUE   # Add a new secret
phantom rotate          # Regenerate all phantom tokens
phantom check           # Pre-commit hook: block real secrets from commits
phantom reveal KEY      # View a real value (stdout or --clipboard)
phantom doctor          # Check configuration and vault health
```

The `phantom check` command works as a pre-commit hook to block any commit containing unprotected secrets in your `.env` or hardcoded keys in staged files.

## Get started

```bash
npx phantom-secrets init
```

- **Website**: [phm.dev](https://phm.dev)
- **GitHub**: [github.com/ashlrai/phantom-secrets](https://github.com/ashlrai/phantom-secrets)
- **Getting started guide**: [phm.dev/docs/getting-started](https://phm.dev/docs/getting-started)

Phantom is open-source (MIT), free for individuals, and has no SaaS dependency. Three commands, and your AI tools can use your real API keys without ever seeing them.
