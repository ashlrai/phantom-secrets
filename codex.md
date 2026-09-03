# Codex Instructions — Phantom Secrets

This project uses **Phantom Secrets** to reduce API-key exposure. Successfully
managed secret entries in the configured dotenv file contain sensitive phantom
placeholders (`phm_...`), not provider credentials; unmanaged files and
undetected entries remain outside that claim.

## Rules

- Do not hardcode API keys in source code.
- Do not ask the user to paste real API key values into code files or chat.
- Do not intentionally read, log, or display stored secret values.
- The `phm_...` values in managed dotenv entries are intentional non-provider
  placeholders. Treat them as sensitive metadata because an active authenticated
  Phantom proxy can use a valid mapping on its exact configured route.

## MCP Tools

Install both binaries from one exact immutable Phantom release, then use
`phantom setup --client codex`. The generated configuration records the bundled
`phantom mcp serve` runtime when resolvable, otherwise a local `phantom-mcp`;
it has no unpinned network package-runner fallback. Representative tools include:

| Tool | Description | Parameters |
|------|-------------|------------|
| `phantom_init` | Protect .env secrets — store in vault, rewrite with phm_ tokens | directory (optional) |
| `phantom_list_secrets` | List secret names with service mappings (never values) | — |
| `phantom_status` | Show vault backend, secret count, project status | — |
| `phantom_add_secret` | **Deprecated** — refuses plaintext via MCP. Use `phantom_add_secret_interactive` instead | name, value |
| `phantom_add_secret_interactive` | Prompt the user on the terminal for a value, then store. Value never crosses the MCP wire | name |
| `phantom_remove_secret` | Request exact transactional removal through the gated compatibility surface | name, confirm, approval_token |
| `phantom_rotate` | Request regeneration of project phantom mappings; provider credentials are unchanged | confirm, approval_token |
| `phantom_cloud_push` | Request a client-encrypted push after separate hosted commissioning and entitlement | confirm, approval_token |
| `phantom_cloud_pull` | Request a pull after separate hosted commissioning and entitlement | force, confirm, approval_token |
| `phantom_cloud_status` | Request cloud status after separate hosted commissioning | confirm, approval_token |

## MCP Setup

One command writes the right config file for Codex (`~/.codex/config.toml`):

```bash
phantom setup --client codex
```

Or print the snippet for manual paste:

```bash
phantom setup --client codex --print
```

Setup fails closed when neither the running `phantom mcp serve` runtime nor a
local `phantom-mcp` can be resolved. Install both binaries from the same exact
release and inspect the generated entry. Consult the live `tools/list` response
for the complete catalog and exact input schemas.

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
3. Phantom's value-blind interfaces are designed not to return stored values.
   Unmanaged files, explicit reveal/export paths, same-user processes, provider
   traffic, and values pasted into a conversation remain outside that boundary.

## When You See API Keys

If a user provides a real API key (`sk-*`, `ghp_*`, `xoxb-*`, etc.):
1. Use `phantom_add_secret_interactive` (the user types the value into their terminal — value never enters the AI context). The deprecated `phantom_add_secret` will refuse plaintext from MCP on purpose.
2. Reference the phantom token in code, never the real value
3. Never write the real key value into any file
