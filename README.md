# Phantom

**AI uses your keys. Safely.**

[![GitHub stars](https://img.shields.io/github/stars/ashlrai/phantom-secrets?style=social)](https://github.com/ashlrai/phantom-secrets/stargazers)
[![CI](https://github.com/ashlrai/phantom-secrets/actions/workflows/ci.yml/badge.svg)](https://github.com/ashlrai/phantom-secrets/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/phantom-secrets)](https://www.npmjs.com/package/phantom-secrets)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![phm.dev](https://img.shields.io/badge/cloud-phm.dev-blue)](https://phm.dev)

AI coding agents read your `.env` files, putting API keys into LLM context windows where they leak via prompt injection, session logs, malicious MCP servers, or training data. GitGuardian reports AI-assisted commits leak secrets at 2x the baseline rate.

Phantom replaces real secrets with inert tokens. A local proxy swaps them back at the network layer. The AI never sees a real key.

## Quick Start

```bash
$ npx phantom-secrets init
# Auto-detects .env, .env.local, or .env in subdirectories
# Stores real secrets in OS keychain, rewrites .env with phantom tokens
# Auto-configures Claude Code MCP server if detected

$ phantom exec -- claude
# Proxy running on 127.0.0.1:54321 — AI sees phantom tokens, proxy injects real keys
```

## How It Works

```
  .env file (safe to leak)          OS Keychain / Vault
  +--------------------------+      +---------------------+
  | OPENAI_API_KEY=phm_a7f3  | ---> | sk-real-secret-key  |
  | STRIPE_KEY=phm_c9d1...   |      | sk_live_real-key... |
  +--------------------------+      +---------------------+
           |                                 |
           v                                 v
  AI Agent (Claude, Cursor)         Phantom Proxy (127.0.0.1)
  +--------------------------+      +------------------------------+
  | Reads .env               |      | Intercepts HTTP requests     |
  | Sees only phm_ tokens    | ---> | Replaces phm_ with real keys |
  | Makes API calls to proxy |      | Forwards over TLS to real API|
  +--------------------------+      +------------------------------+
```

1. `phantom init` reads `.env`, stores real secrets in the OS keychain, rewrites `.env` with `phm_` tokens
2. `phantom exec -- claude` starts a local reverse proxy, sets `OPENAI_BASE_URL=http://127.0.0.1:PORT/openai` (and equivalents for other services)
3. API calls hit the proxy, which replaces phantom tokens with real secrets and forwards over TLS
4. When the session ends, the proxy shuts down. Phantom tokens are worthless outside the proxy.

## MCP Integration (Claude Code, Cursor, Windsurf)

Phantom ships an MCP server so AI coding tools can manage secrets directly -- without ever seeing real values. 9 tools available: list, status, init, add, remove, rotate, cloud push, cloud pull, cloud status.

### Claude Code
```bash
$ claude mcp add phantom-secrets-mcp -- npx phantom-secrets-mcp
```

### Cursor
Add to Cursor Settings > Features > MCP Servers:
- Name: `phantom`
- Command: `npx phantom-secrets-mcp`

### Windsurf
Add to `~/.codeium/windsurf/mcp_config.json`:
```json
{"phantom": {"command": "npx", "args": ["phantom-secrets-mcp"]}}
```

Or run `phantom setup` to auto-configure Claude Code.

## Cloud Sync

Sync vaults across machines with end-to-end encryption. The server never sees plaintext.

```bash
$ phantom login
# Opens GitHub OAuth (device code flow)

$ phantom cloud push
# Encrypted client-side, uploaded to phm.dev

$ phantom cloud pull   # on another machine
# Downloaded and decrypted locally
```

Cloud sync uses ChaCha20-Poly1305 with a client-side passphrase derived via Argon2id. The server stores only ciphertext.

## Command Reference

| Command | Description |
|---------|-------------|
| `phantom init` | Import `.env` secrets into vault, rewrite with phantom tokens |
| `phantom exec -- <cmd>` | Start proxy and run a command with secret injection |
| `phantom start` / `stop` | Manage proxy lifecycle (standalone/daemon mode) |
| `phantom list` | Show secret names stored in vault (never values) |
| `phantom add <KEY> <VAL>` | Add a secret to the vault |
| `phantom remove <KEY>` | Remove a secret from the vault |
| `phantom reveal <KEY>` | Print a secret value (or `--clipboard` to copy) |
| `phantom status` | Show proxy state, vault info, and mapped services |
| `phantom rotate` | Regenerate all phantom tokens (old ones become invalid) |
| `phantom doctor` | Check configuration and vault health |
| `phantom check` | Scan for unprotected secrets (pre-commit hook) |
| `phantom sync` | Push secrets to Vercel / Railway |
| `phantom pull` | Pull secrets from Vercel / Railway into vault |
| `phantom setup` | Configure Claude Code MCP server + hooks |
| `phantom env` | Generate `.env.example` for team onboarding |
| `phantom export` | Export vault to encrypted backup file |
| `phantom import` | Import vault from encrypted backup |
| `phantom login` | Authenticate with Phantom Cloud via GitHub OAuth |
| `phantom logout` | Clear cloud credentials |
| `phantom cloud push` | Push encrypted vault to Phantom Cloud |
| `phantom cloud pull` | Pull and decrypt vault from Phantom Cloud |

## Features

- **Encrypted vault** -- OS keychain (macOS Keychain / Secure Enclave, Linux Secret Service) with encrypted file fallback for CI/Docker
- **Session-scoped tokens** -- 256-bit CSPRNG phantom tokens with `phm_` prefix, rotatable on demand
- **Streaming proxy** -- Full SSE/streaming support for OpenAI, Anthropic, and other streaming APIs
- **Smart detection** -- Heuristic engine distinguishes secrets (`*_KEY`, `*_TOKEN`, `sk-*`, `ghp_*`) from config (`NODE_ENV`, `PORT`)
- **Platform sync** -- Push/pull secrets to Vercel and Railway
- **Pre-commit hook** -- Blocks commits containing unprotected secrets
- **MCP server** -- 9 tools for Claude Code to manage secrets without seeing values
- **Cloud sync** -- E2E encrypted zero-knowledge vault sync across machines
- **Export/import** -- Encrypted backup and restore with passphrase protection
- **Built-in service routing** -- OpenAI, Anthropic, Stripe, Supabase, and custom services via `.phantom.toml`

## Installation

### npm (recommended)

```bash
$ npm install -g phantom-secrets
```

Or use directly with npx:

```bash
$ npx phantom-secrets init
```

### Claude Code MCP

```bash
$ claude mcp add phantom-secrets-mcp -- npx phantom-secrets-mcp
```

### Cargo

```bash
$ cargo install phantom
```

## Architecture

5-crate Rust workspace + Next.js cloud backend:

| Crate | Role |
|-------|------|
| `phantom-core` | Config (`.phantom.toml`), `.env` parsing/rewriting, token generation, auth, cloud client |
| `phantom-vault` | `VaultBackend` trait: OS keychain + encrypted file fallback, ChaCha20-Poly1305 crypto |
| `phantom-proxy` | HTTP reverse proxy on 127.0.0.1 with SSE/streaming, token replacement, TLS forwarding |
| `phantom-cli` | `clap`-based CLI binary, 21 commands |
| `phantom-mcp` | MCP server binary (`rmcp` SDK), stdio transport, 9 tools |

**`apps/web`** -- Next.js backend at [phm.dev](https://phm.dev) for cloud vault sync, GitHub OAuth, and Stripe billing.

**npm packages**: [`phantom-secrets`](https://www.npmjs.com/package/phantom-secrets) (CLI), [`phantom-secrets-mcp`](https://www.npmjs.com/package/phantom-secrets-mcp) (MCP server).

56 tests across all crates, zero clippy warnings.

## Security

- **Secrets never on disk** in your project directory -- real values live only in the OS keychain or encrypted vault
- **ChaCha20-Poly1305** encryption for file vault and cloud sync, **Argon2id** key derivation
- **Zero-knowledge cloud** -- server stores only ciphertext; encryption key never leaves the client
- **256-bit CSPRNG tokens** -- `phm_` prefix ensures they never collide with real API key formats
- **Proxy binds 127.0.0.1 only** -- never exposed to the network
- **Secrets zeroized from memory** after injection via the `zeroize` crate
- **Allowlist model** -- proxy only injects secrets for explicitly configured service patterns

See [SECURITY.md](SECURITY.md) for the full threat model.

## Pricing

| | Free | Pro | Enterprise |
|---|---|---|---|
| Local vaults | Unlimited | Unlimited | Unlimited |
| Cloud vaults | 1 | Unlimited | Unlimited |
| MCP server | Yes | Yes | Yes |
| Cloud sync | Yes | Yes | Yes |
| Team features | -- | -- | Yes |
| Price | $0 | $8/mo | Contact us |

## Links

- [phm.dev](https://phm.dev) -- Cloud dashboard and account management
- [Getting Started Guide](docs/getting-started.md)
- [Security Model](SECURITY.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Contributing](CONTRIBUTING.md)

## License

MIT -- see [LICENSE](LICENSE)
