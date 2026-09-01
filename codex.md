# Codex Instructions — Phantom Secrets

This project uses **Phantom Secrets** to reduce API-key exposure. Successfully
managed secret entries in the configured dotenv file contain sensitive phantom
placeholders (`phm_...`), not provider credentials; unmanaged files and
undetected entries remain outside that claim.

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
| `phantom_add_secret` | **Deprecated** — refuses plaintext via MCP. Use `phantom_add_secret_interactive` instead | name, value |
| `phantom_add_secret_interactive` | Prompt the user on the terminal for a value, then store. Value never crosses the MCP wire | name |
| `phantom_remove_secret` | Remove a secret from the vault | name |
| `phantom_rotate` | Regenerate all phantom tokens in .env | — |
| `phantom_cloud_push` | Push encrypted vault to Phantom Cloud | — |
| `phantom_cloud_pull` | Pull vault from Phantom Cloud | force (bool) |
| `phantom_cloud_status` | Check cloud auth and sync status | — |

## MCP Setup

One command writes the right config file for Codex (`~/.codex/config.toml`):

```bash
phantom setup --client codex
```

Or print the snippet for manual paste:

```bash
phantom setup --client codex --print
```

Released `v0.7.3` retains a final unpinned npm fallback. Current 0.7.4 source
removes that network fallback and fails closed when neither the running
`phantom mcp serve` runtime nor a local `phantom-mcp` can be resolved. Install
both exact release binaries and inspect the generated entry.

## CLI Commands

- `phantom list` — See available secrets (never shows values)
- `phantom add <name>` — Add a secret transactionally through the trusted terminal's hidden prompt; run `phantom init --empty` first in a new project
- `phantom exec -- <command>` — Run code through Phantom's authenticated, configured HTTP routes
- `phantom init` — Protect .env secrets
- `phantom doctor` — Health check

## How It Works

1. `phantom init` reads `.env`, stores real secrets in encrypted vault, rewrites `.env` with `phm_` tokens
2. `phantom exec -- <cmd>` starts an authenticated local proxy. After an exact
   route match, the proxy discards client control of that route's auth header
   and injects only the route-owned vault value into the fixed header. Client
   headers and bodies never resolve phantom tokens.
3. AI agents see only worthless `phm_` tokens — real keys never enter the AI context window

## When You See API Keys

If a user provides a real API key (`sk-*`, `ghp_*`, `xoxb-*`, etc.):
1. Use `phantom_add_secret_interactive` (the user types the value into their terminal — value never enters the AI context). The deprecated `phantom_add_secret` will refuse plaintext from MCP on purpose.
2. Reference the phantom token in code, never the real value
3. Never write the real key value into any file
