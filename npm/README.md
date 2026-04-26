# Phantom Secrets

**AI uses your keys. Safely.**

[![npm](https://img.shields.io/npm/v/phantom-secrets)](https://www.npmjs.com/package/phantom-secrets)
[![GitHub stars](https://img.shields.io/github/stars/ashlrai/phantom-secrets?style=social)](https://github.com/ashlrai/phantom-secrets/stargazers)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/ashlrai/phantom-secrets/blob/main/LICENSE)

AI coding agents read your `.env` files, putting API keys into LLM context windows where they can leak via prompt injection, session logs, malicious MCP servers, or training data.

Phantom replaces real secrets with inert `phm_` tokens. A local reverse proxy swaps them back at the network layer. **The AI never sees a real key.**

## Install

```bash
npm install -g phantom-secrets
```

Or run directly:

```bash
npx phantom-secrets init
```

## Quick Start

```bash
# Protect your secrets
$ npx phantom-secrets init
# Detects .env files, stores real secrets in OS keychain,
# rewrites .env with phantom tokens

# Run your AI tool through the proxy
$ phantom exec -- claude
# Proxy on 127.0.0.1 swaps phm_ tokens with real keys at the network layer
```

## How It Works

1. `phantom init` reads `.env`, stores real secrets in the OS keychain, rewrites values with `phm_` tokens
2. `phantom exec -- claude` starts a local reverse proxy that sets `OPENAI_BASE_URL=http://127.0.0.1:PORT/openai` (and equivalents)
3. API calls hit the proxy, which replaces phantom tokens with real secrets and forwards over TLS
4. When the session ends, the proxy shuts down. Phantom tokens are worthless outside the proxy.

## 27 Commands

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
| `phantom doctor` | Check configuration and vault health (`--fix` to auto-repair) |
| `phantom check` | Scan for unprotected secrets (pre-commit hook, `--staged`, `--runtime`) |
| `phantom wrap` | Wrap package.json scripts with `phantom exec` automatically |
| `phantom unwrap` | Restore original package.json scripts |
| `phantom watch` | Watch .env files and auto-detect new unprotected secrets |
| `phantom why <KEY>` | Explain why a key is or is not protected |
| `phantom copy <KEY> --to <dir>` | Copy a secret to another project's vault |
| `phantom sync` | Push secrets to Vercel / Railway |
| `phantom pull` | Pull secrets from Vercel / Railway into vault |
| `phantom setup` | Configure Claude Code MCP server + hooks |
| `phantom env` | Generate `.env.example` for team onboarding |
| `phantom export` | Export vault to encrypted backup file |
| `phantom import` | Import vault from encrypted backup |
| `phantom login` / `logout` | Authenticate with Phantom Cloud via GitHub OAuth |
| `phantom cloud push` | Push encrypted vault to Phantom Cloud |
| `phantom cloud pull` | Pull and decrypt vault from Phantom Cloud |
| `phantom team list/create/members/invite` | Team vault management |

## MCP Server

Phantom ships a companion MCP server package so AI coding tools can manage secrets directly -- without ever seeing real values. 24 tools available.

```bash
# Claude Code
claude mcp add phantom-secrets-mcp -- npx phantom-secrets-mcp

# Cursor / Windsurf / Codex
# Add to your MCP config:
{"phantom": {"command": "npx", "args": ["phantom-secrets-mcp"]}}
```

See [`phantom-secrets-mcp`](https://www.npmjs.com/package/phantom-secrets-mcp) on npm.

## Key Features

- **OS keychain storage** -- macOS Keychain / Secure Enclave, Linux Secret Service, encrypted file fallback for CI
- **256-bit CSPRNG tokens** -- `phm_` prefix, rotatable on demand
- **Streaming proxy** -- Full SSE/streaming support for OpenAI, Anthropic, and other APIs
- **Response scrubbing** -- Prevents secrets from leaking in API responses back to the AI
- **Smart detection** -- Heuristic engine distinguishes secrets from config values
- **Platform sync** -- Push/pull secrets to Vercel and Railway
- **Cloud sync** -- E2E encrypted zero-knowledge vault sync across machines (ChaCha20-Poly1305 + Argon2id)
- **Team vaults** -- Shared vaults with role-based access control
- **Pre-commit hook** -- Blocks commits containing unprotected secrets
- **Script wrapping** -- `phantom wrap` patches package.json so every npm script runs through the proxy
- **Watch mode** -- `phantom watch` monitors .env files for new unprotected secrets
- **Export/import** -- Encrypted backup and restore with passphrase protection

## Platform Support

| Platform | Architecture | Status |
|----------|-------------|--------|
| macOS | Apple Silicon (arm64) | Supported |
| macOS | Intel (x64) | Supported |
| Linux | x64 | Supported |
| Linux | arm64 | Supported |

## Security

- Secrets never on disk in your project directory
- Proxy binds to 127.0.0.1 only -- never exposed to the network
- Secrets zeroized from memory after injection
- Zero-knowledge cloud -- server stores only ciphertext

See [SECURITY.md](https://github.com/ashlrai/phantom-secrets/blob/main/SECURITY.md) for the full threat model.

## Links

- [phm.dev](https://phm.dev) -- Cloud dashboard
- [GitHub](https://github.com/ashlrai/phantom-secrets)
- [Getting Started](https://github.com/ashlrai/phantom-secrets/blob/main/docs/getting-started.md)
- [MCP Server](https://www.npmjs.com/package/phantom-secrets-mcp)

## License

MIT
