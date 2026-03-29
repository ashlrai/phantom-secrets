# How AI coding tools leak your API keys (and how we fixed it)

You paste API keys into Claude Code. You let Cursor read your `.env`. You tell Copilot to "use the Stripe key in my environment" and watch it wire up a payment flow in thirty seconds. You know it's risky. You do it anyway, because AI doing your work is worth it.

You're not alone. GitGuardian's 2025 State of Secrets Sprawl report found 39.6 million secrets leaked in public repositories -- an 81% year-over-year increase. The kicker: commits from AI-assisted development leak secrets at **twice the baseline rate**. The tools that make us most productive are also the most prolific secret-leakers in the history of software development.

We built [Phantom](https://phm.dev) to fix this without asking you to change how you work.

## Why AI tools leak secrets

The root cause is architectural. Every AI coding tool follows the same pattern:

1. You have a `.env` file with `OPENAI_API_KEY=sk-proj-abc123...`
2. The AI agent reads that file to understand your project
3. Your real API key is now inside the LLM context window

Once a secret is in the context window, every downstream system becomes an attack surface:

- **Session logs** -- most AI tools persist conversation history to disk. Your API key is sitting in a JSON file somewhere in `~/.claude/` or `~/.cursor/`.
- **Prompt injection** -- a malicious README, dependency, or comment can instruct the LLM to exfiltrate environment variables. Check Point Research demonstrated this with CVE-2025-59536 (Cursor) and CVE-2026-21852 (Claude Code): crafted prompts that trick the agent into sending secrets to attacker-controlled servers.
- **Malicious MCP servers** -- the Model Context Protocol lets AI tools call external services. A compromised or malicious MCP server can request environment context and receive your real keys.
- **Training data** -- despite opt-out policies, secrets that enter an LLM provider's API have a nonzero chance of influencing future model behavior.

The common advice -- "just don't put secrets in `.env`" -- ignores reality. Developers need secrets in their environment to build software. The question isn't whether AI will read your `.env`. It's what it finds when it does.

## The phantom token pattern

Phantom takes a different approach: let the AI read your `.env`, but make sure there's nothing real in it.

Here's what your `.env` looks like before and after:

```
# Before phantom
OPENAI_API_KEY=sk-proj-abc123def456ghi789...
STRIPE_SECRET_KEY=sk_live_51HG7a9s8d7f6g5h4j3k2l1...
DATABASE_URL=postgresql://admin:s3cret@db.example.com:5432/prod

# After phantom
OPENAI_API_KEY=phm_a7f3b9e2d1c4f8a6b3e7d2c5f9a1b4e8...
STRIPE_SECRET_KEY=phm_c3d7f2a9e1b5d8c4a7f3b6e2d9c1a5f8...
DATABASE_URL=phm_e8b2d5a9c3f7e1b4d8a2c6f3e7b1d5a9...
```

Those `phm_` tokens are 256-bit CSPRNG values. They look like API keys. They parse like API keys. But they are cryptographically worthless. If an AI agent leaks one, if it ends up in a session log, if a prompt injection exfiltrates it -- nothing happens. It's not a real credential.

Your real secrets are stored in the OS keychain (macOS Keychain with Secure Enclave on Apple Silicon, Linux Secret Service, or an encrypted file fallback for CI).

The magic happens at the network layer.

## How the proxy works

When you run `phantom exec -- claude`, Phantom starts a local HTTP reverse proxy on `127.0.0.1` and rewrites the base URLs in your environment:

```
OPENAI_BASE_URL=http://127.0.0.1:54321/openai
ANTHROPIC_BASE_URL=http://127.0.0.1:54321/anthropic
STRIPE_API_BASE=http://127.0.0.1:54321/stripe
```

This is not a CONNECT tunnel or a transparent MITM proxy. It's a standard reverse proxy. When your code (or the AI agent's code) makes an API call to OpenAI, the request goes to `127.0.0.1:54321/openai/v1/chat/completions`. The proxy:

1. Scans the request headers and body for phantom tokens (`phm_...`)
2. Looks up the corresponding real secret from the vault
3. Replaces the phantom token with the real credential
4. Forwards the request over TLS to `api.openai.com`
5. Zeroizes the real secret from memory after injection

The AI agent never sees the real key. Your code doesn't need to change. Every SDK that supports `BASE_URL` configuration (which is all of them -- OpenAI, Anthropic, Stripe, Supabase) works without modification.

When the `exec` session ends, the proxy shuts down. The phantom tokens become inert -- there's no running proxy to resolve them. They're session-scoped by design.

### Why this architecture works

The reverse proxy pattern is sound for a few reasons:

- **No certificate manipulation** -- unlike MITM proxies, Phantom doesn't need to inject CA certificates or break TLS. The proxy terminates the plaintext connection locally and initiates a fresh TLS connection to the upstream API.
- **Allowlist model** -- the proxy only injects secrets for explicitly configured service patterns. A request to an unknown host receives the phantom token unchanged, which simply fails as an invalid key. No secret leakage to unexpected destinations.
- **Localhost only** -- the proxy binds to `127.0.0.1`, never to `0.0.0.0`. It's not reachable from the network.
- **Ephemeral ports** -- each session gets a random port, reducing the window for local process abuse.

For the vault, Phantom uses ChaCha20-Poly1305 for encryption with Argon2id for key derivation (when using the encrypted file fallback instead of OS keychain). The `zeroize` crate scrubs secrets from memory after every proxy injection.

## Getting started

Three commands. Ten seconds.

```bash
# Initialize -- imports .env secrets, rewrites with phantom tokens
phantom init
# => Found 3 secret(s) to protect: OPENAI_API_KEY, ANTHROPIC_API_KEY, DATABASE_URL
# => Rewrote .env with phantom tokens
# => Saved real secrets to OS keychain

# Work with AI -- proxy starts, wraps your command
phantom exec -- claude
# => Proxy running on 127.0.0.1:54321
# => Claude Code sees phantom tokens, proxy injects real keys

# Deploy -- push real secrets to your platform
phantom sync --platform vercel
# => Synced 3 secrets to Vercel (real values, not phantom tokens)
```

Other things you can do:

```bash
phantom status          # See what's protected and proxy state
phantom add KEY VALUE   # Add a new secret
phantom rotate          # Regenerate all phantom tokens
phantom check           # Pre-commit hook: block unprotected secrets
phantom reveal KEY      # View a real value (stdout or --clipboard)
phantom setup           # Configure Claude Code MCP integration
```

Phantom also ships an MCP server so Claude Code can manage secrets natively -- listing, adding, rotating -- without ever seeing a real value.

## Why not existing tools?

We looked at the landscape before building this.

**1Password / Vault** -- Enterprise-grade, closed-source, $8/user/month. The `op run` pattern is similar in spirit, but 1Password has no awareness of AI context windows, no proxy pattern, no phantom tokens. If your AI agent calls `op read`, the real secret enters the context.

**Doppler** -- Good centralized secret management, but focused on deployment pipelines, not developer workstations. No concept of AI-safe secrets. No local proxy.

**Infisical** -- Open-source secret management with a nice dashboard. But same problem: secrets are injected as real environment variables. The AI reads them. No proxy pattern.

**dotenvx** -- Encrypts `.env` files, which is useful for storage. But at runtime, secrets are decrypted into real environment variables. The AI sees them.

The gap is clear: existing tools protect secrets at rest and in transit between humans and servers. None of them address the AI agent in the middle -- the one that reads your `.env`, holds secrets in a context window, and can be manipulated into leaking them.

Phantom is:

- **Open-source** (MIT) -- read every line of code that touches your secrets
- **AI-native** -- built specifically for the AI coding tool threat model
- **Developer-first** -- no dashboard, no signup, no SaaS dependency
- **Free for individuals** -- and always will be

## What's next

Since launch, we've added **cloud sync** -- end-to-end encrypted vault backup across machines (`phantom login` + `phantom cloud push/pull`), **export/import** for offline vault backups, and **streaming proxy support** for SSE/streaming responses. We're now working on team features (shared phantom vaults, secret rotation policies, audit logs) and expanding the built-in service patterns. The core proxy pattern and CLI will remain free and open-source.

If you've ever pasted an API key into an AI chat and felt a twinge of guilt, this is for you.

## Get started

```bash
npx phantom-secrets init
```

- **Website**: [phm.dev](https://phm.dev)
- **GitHub**: [github.com/ashlrai/phantom-secrets](https://github.com/ashlrai/phantom-secrets)
- **Docs**: [phm.dev/docs/getting-started](https://phm.dev/docs/getting-started)

Star the repo if this solves a problem you've been ignoring. We've all been ignoring it.
