# Phantom Secrets MCP Server

**Value-blind secrets management over MCP.** Lets Claude Code, Cursor,
Windsurf, and Codex inspect metadata and request gated lifecycle operations
without MCP responses returning real values.

[![npm](https://img.shields.io/npm/v/phantom-secrets-mcp)](https://www.npmjs.com/package/phantom-secrets-mcp)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/ashlrai/phantom-secrets/blob/main/LICENSE)

Part of [Phantom Secrets](https://www.npmjs.com/package/phantom-secrets) -- the
CLI that replaces project secrets with scoped `phm_` tokens and gives agents
value-blind secret-management tools.

## Install

### Claude Code

```bash
claude mcp add phantom-secrets-mcp -- npx -y phantom-secrets-mcp
```

### Cursor

Add to Cursor Settings > Features > MCP Servers:
- Name: `phantom`
- Command: `npx`
- Args: `-y phantom-secrets-mcp`

### Windsurf

Add to `~/.codeium/windsurf/mcp_config.json`:

```json
{
  "mcpServers": {
    "phantom": {
      "command": "npx",
      "args": ["-y", "phantom-secrets-mcp"]
    }
  }
}
```

### Codex

Add to `~/.codex/config.toml`:

```toml
[mcp_servers.phantom]
command = "npx"
args = ["-y", "phantom-secrets-mcp"]
```

### Other MCP Clients

Add to your MCP configuration:

```json
{
  "mcpServers": {
    "phantom": {
      "command": "npx",
      "args": ["-y", "phantom-secrets-mcp"]
    }
  }
}
```

Works with any tool that supports the [Model Context Protocol](https://modelcontextprotocol.io).

## MCP Tools

The MCP server exposes core secret-management tools plus advanced audit, validation, rotation, expiry, team-vault, and compliance workflows. The registry metadata is generated from the server's live tool declarations; this README summarizes the main groups.

Conversation, status, and validation tools:

Responses do not contain secret values. `phantom_setup_workspace` proposal may
provision or harden machine-local Phantom state, and `phantom_validate_all`
performs provider network calls and persists safe validation metadata.

| Tool | Description |
|------|-------------|
| `phantom_capability` | Report the conversation facade's authority and hard denials; advanced compatibility tools are separately gated |
| `phantom_do` | Propose one closed Cargo action and return its digest/effect/blockers without execution |
| `phantom_setup_workspace` | Propose value-blind setup, create a bearerless trusted-terminal request, or read authenticated status; proposal checks/hardens machine-local state and reports key provisioning |
| `phantom_list_secrets` | List secret names in the vault (never exposes values) |
| `phantom_status` | Check project configuration, vault health, and proxy state |
| `phantom_doctor` | Diagnose configuration and vault health |
| `phantom_why` | Explain why a key is or is not protected |
| `phantom_check` | Scan for unprotected secrets (pre-commit-style) |
| `phantom_sync` | Preview deployment-platform sync (Vercel, Railway) |
| `phantom_cloud_status` | Check cloud authentication and sync status |
| `phantom_validate_secret` | Show last-known credential validation status for one secret |
| `phantom_validate_all` | Run live health checks for stored credentials and persist safe metadata |

Mutating tools (modify vault or `.env`):

| Tool | Description |
|------|-------------|
| `phantom_init` | Protect secrets in .env files -- store in vault, rewrite with phantom tokens |
| `phantom_env` | Generate `.env.example` with secrets replaced by placeholders |
| `phantom_add_secret_interactive` | Start a terminal prompt for adding a secret without passing the value through MCP |
| `phantom_add_secret` | Deprecated compatibility tool; refuses plaintext values through MCP |
| `phantom_remove_secret` | Remove a secret from the vault |
| `phantom_rotate` | Regenerate all phantom tokens (invalidates old ones) |
| `phantom_copy_secret` | Copy a secret from this project to another project's vault |
| `phantom_wrap` | Wrap `package.json` scripts with `npx phantom-secrets exec` so npm scripts run through the proxy |
| `phantom_unwrap` | Restore original `package.json` scripts from `:raw` variants |
| `phantom_cloud_push` | Push encrypted vault to Phantom Cloud (E2E encrypted) |
| `phantom_cloud_pull` | Pull and decrypt vault from Phantom Cloud |
| `phantom_rotate_with_candidate` | Create a staged candidate credential without exposing values |
| `phantom_rotate_promote` | Promote a validated staged candidate to primary |
| `phantom_rotate_provider` | Rotate through a configured provider such as Stripe, GitHub, or AWS |
| `phantom_rotate_with_expiry` | Rotate tokens and set TTL metadata on vault entries |
| `phantom_secrets_auto_rotate` | Refresh one secret's token and expiry metadata |

Team vault tools (Pro plan; multi-developer shared vaults):

| Tool | Description |
|------|-------------|
| `phantom_team_list` | List teams the user belongs to (read-only) |
| `phantom_team_create` | Create a new team. Caller becomes owner |
| `phantom_team_members` | List members of a team (read-only) |
| `phantom_team_invite` | Invite someone to a team by GitHub username |
| `phantom_team_key_publish` | Register the caller's X25519 public key on a team |
| `phantom_team_vault_push` | Push the current project's vault to a team (envelope-encrypted to every registered member) |
| `phantom_team_vault_pull` | Pull the team vault into the local vault |

Audit, compliance, and expiry tools:

| Tool | Description |
|------|-------------|
| `phantom_audit_recent` | Read recent audit events without values |
| `phantom_audit_stats` | Aggregate audit access counts and anomaly scores |
| `phantom_audit_anomalies` / `phantom_audit_anomalies_realtime` | Find suspicious access patterns |
| `phantom_audit_hotspot_alerts` | Inspect and optionally acknowledge access-velocity alerts |
| `phantom_audit_analytics` | Export audit analytics for dashboards |
| `phantom_audit_incidents` / `phantom_leak_incidents_realtime` | Summarize leak incidents without exposing values |
| `phantom_audit_alerts` / `phantom_audit_export_report` | Read alert records or generate compliance reports |
| `phantom_compliance_status` | Report compliance readiness for the current project |
| `phantom_secret_rotation_due` / `phantom_list_with_expiry` | Show rotation and expiry status |
| `phantom_secrets_expiry_check` / `phantom_expiry_enforce` | Check expired secrets and policy violations |
| `phantom_rotation_schedule_next` / `phantom_apply_expiry_policy` | Inspect rotation schedules and apply expiry demotion policy |
| `phantom_validation_schedule` / `phantom_validation_history` | Manage validation cadence and read validation history |

MCP responses do not return actual secret values, and the deprecated plaintext
add tool rejects values passed through MCP. Agents can manage value-blind
metadata and request gated lifecycle operations (add, remove, rotate, sync,
share with teams, audit, validate, and enforce expiry). Mutating tools require
`confirm: true`; higher-risk tools also use the separate MCP approval gate.

## How It Works

1. The MCP server runs as a stdio transport process alongside your AI coding tool
2. When the AI needs to manage secrets, it calls Phantom MCP tools
3. Phantom stores real secrets in the native credential store (macOS Keychain, Linux Secret Service, or Windows Credential Manager) or a ChaCha20-Poly1305 encrypted-file vault
4. Agents use value-blind MCP metadata; application processes load tokens for authenticated proxy sessions
5. A local reverse proxy swaps tokens back at the network layer when making API calls

## Requirements

- [Phantom Secrets CLI](https://www.npmjs.com/package/phantom-secrets) must be initialized in your project (`npx phantom-secrets init`)
- Node.js >= 16
- A published macOS (arm64/x64), glibc Linux (x64/arm64), or Windows (x64/arm64) release target. See the [platform support matrix](https://github.com/ashlrai/phantom-secrets/blob/main/docs/platform-support.md) for native-integration and acceptance limits.

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
