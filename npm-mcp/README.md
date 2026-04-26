# Phantom Secrets MCP Server

**MCP server for AI-safe secrets management.** Lets Claude Code, Cursor, Windsurf, and Codex manage API keys without ever seeing real values.

[![npm](https://img.shields.io/npm/v/phantom-secrets-mcp)](https://www.npmjs.com/package/phantom-secrets-mcp)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/ashlrai/phantom-secrets/blob/main/LICENSE)

Part of [Phantom Secrets](https://www.npmjs.com/package/phantom-secrets) -- the CLI that replaces real secrets with inert `phm_` tokens so AI agents never see your API keys.

## Install

### Claude Code

```bash
claude mcp add phantom-secrets-mcp -- npx phantom-secrets-mcp
```

### Cursor

Add to Cursor Settings > Features > MCP Servers:
- Name: `phantom`
- Command: `npx phantom-secrets-mcp`

### Windsurf

Add to `~/.codeium/windsurf/mcp_config.json`:

```json
{
  "phantom": {
    "command": "npx",
    "args": ["phantom-secrets-mcp"]
  }
}
```

### Codex / Other MCP Clients

Add to your MCP configuration:

```json
{
  "phantom": {
    "command": "npx",
    "args": ["phantom-secrets-mcp"]
  }
}
```

Works with any tool that supports the [Model Context Protocol](https://modelcontextprotocol.io).

## 17 MCP Tools

Read-only tools (safe to call anytime):

| Tool | Description |
|------|-------------|
| `phantom_list_secrets` | List secret names in the vault (never exposes values) |
| `phantom_status` | Check project configuration, vault health, and proxy state |
| `phantom_doctor` | Diagnose configuration and vault health |
| `phantom_why` | Explain why a key is or is not protected |
| `phantom_check` | Scan for unprotected secrets (pre-commit-style) |
| `phantom_env` | List environment variables with protection status (no values) |
| `phantom_sync` | Preview deployment-platform sync (Vercel, Railway) |
| `phantom_cloud_status` | Check cloud authentication and sync status |

Mutating tools (modify vault or `.env`):

| Tool | Description |
|------|-------------|
| `phantom_init` | Protect secrets in .env files -- store in vault, rewrite with phantom tokens |
| `phantom_add_secret` | Add a new secret to the vault |
| `phantom_remove_secret` | Remove a secret from the vault |
| `phantom_rotate` | Regenerate all phantom tokens (invalidates old ones) |
| `phantom_copy_secret` | Copy a secret from this project to another project's vault |
| `phantom_wrap` | Wrap a plaintext `.env` value into a vaulted `phm_` token |
| `phantom_unwrap` | Reverse a wrap (restore plaintext to `.env` from vault) |
| `phantom_cloud_push` | Push encrypted vault to Phantom Cloud (E2E encrypted) |
| `phantom_cloud_pull` | Pull and decrypt vault from Phantom Cloud |

All tools are read-safe: they never return actual secret values. The AI can manage your secrets lifecycle (add, remove, rotate, sync) without any risk of key exposure.

## How It Works

1. The MCP server runs as a stdio transport process alongside your AI coding tool
2. When the AI needs to manage secrets, it calls Phantom MCP tools
3. Phantom stores real secrets in the OS keychain (macOS Keychain, Linux Secret Service) or encrypted file vault
4. The AI only ever sees `phm_` phantom tokens -- never real API keys
5. A local reverse proxy swaps tokens back at the network layer when making API calls

## Requirements

- [Phantom Secrets CLI](https://www.npmjs.com/package/phantom-secrets) must be initialized in your project (`npx phantom-secrets init`)
- Node.js >= 16
- macOS (arm64/x64) or Linux (x64/arm64)

## Cloud Sync

The MCP server includes cloud push/pull tools for syncing vaults across machines:

```
AI: "Push this project's secrets to the cloud"
-> phantom_cloud_push (E2E encrypted with ChaCha20-Poly1305, Argon2id key derivation)

AI: "Pull secrets from the cloud to this machine"
-> phantom_cloud_pull (decrypted locally, server never sees plaintext)
```

Requires `phantom login` (GitHub OAuth) via the CLI first.

## Links

- [Phantom Secrets CLI](https://www.npmjs.com/package/phantom-secrets)
- [GitHub](https://github.com/ashlrai/phantom-secrets)
- [phm.dev](https://phm.dev) -- Cloud dashboard
- [Security Model](https://github.com/ashlrai/phantom-secrets/blob/main/SECURITY.md)

## License

MIT
