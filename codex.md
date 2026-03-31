# Codex Instructions — Phantom Secrets

This project uses **Phantom Secrets** to protect API keys from AI leaks. The `.env` file contains phantom tokens (`phm_...`), not real secrets.

## Rules

- NEVER hardcode API keys in source code
- NEVER ask the user to paste real API key values into code files
- NEVER attempt to read, log, or display real secret values
- The `phm_...` tokens in `.env` are intentional — they are worthless placeholders

## MCP Tools

Phantom provides an MCP server (`npx phantom-secrets-mcp`) with these tools:

| Tool | Description | Parameters |
|------|-------------|------------|
| `phantom_init` | Protect .env secrets — store in vault, rewrite with phm_ tokens | directory (optional) |
| `phantom_list_secrets` | List secret names with service mappings (never values) | — |
| `phantom_status` | Show vault backend, secret count, project status | — |
| `phantom_add_secret` | Add a new secret to the vault | name, value |
| `phantom_remove_secret` | Remove a secret from the vault | name |
| `phantom_rotate` | Regenerate all phantom tokens in .env | — |
| `phantom_cloud_push` | Push encrypted vault to Phantom Cloud | — |
| `phantom_cloud_pull` | Pull vault from Phantom Cloud | force (bool) |
| `phantom_cloud_status` | Check cloud auth and sync status | — |

## MCP Setup

```json
{"phantom": {"command": "npx", "args": ["phantom-secrets-mcp"]}}
```

## CLI Commands

- `phantom list` — See available secrets (never shows values)
- `phantom add <name> <value>` — Add a new secret
- `phantom exec -- <command>` — Run code with real credentials injected via proxy
- `phantom init` — Protect .env secrets
- `phantom doctor` — Health check

## How It Works

1. `phantom init` reads `.env`, stores real secrets in encrypted vault, rewrites `.env` with `phm_` tokens
2. `phantom exec -- <cmd>` starts a local proxy that swaps phantom tokens for real credentials
3. AI agents see only worthless `phm_` tokens — real keys never enter the AI context window

## When You See API Keys

If a user provides a real API key (`sk-*`, `ghp_*`, `xoxb-*`, etc.):
1. Use `phantom_add_secret` to store it in the vault
2. Reference the phantom token in code, never the real value
3. Never write the real key value into any file
