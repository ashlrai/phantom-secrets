# Phantom Secrets MCP Server

<!-- mcp-name: io.github.ashlrai/phantom-secrets-mcp -->

An MCP (Model Context Protocol) server for value-blind Phantom secret
management and gated lifecycle requests.

## What it does

Phantom Secrets replaces real secrets in managed `.env` files with opaque
**phantom tokens** (`phm_...`). Agents use value-blind metadata while
application processes load tokens for authenticated proxy sessions. When the
application makes an allowlisted API call, the local proxy injects the matching
credential at the network boundary.

The MCP server lets AI agents manage value-blind metadata and request gated
lifecycle operations. MCP responses do not return actual secret values; the
trusted terminal and local runtime remain separate security boundaries.

Provider consent and `phantom grant` issuance are not MCP tools. They run in a
trusted terminal, and their provider grants are credential lifecycle state,
not inactive execution-kernel authority grants. Provider grants confer no
Locus authority, broker lease, or execution permit.

## Tools

The server exposes Phantom's live MCP catalog over stdio transport. The registry metadata tracks the exact tool names; this README summarizes the main groups so it stays readable.

**Conversation, status, and validation operations (responses do not return secret values):**

`phantom_setup_workspace` proposal may provision or harden machine-local Phantom
state, and `phantom_validate_all` performs provider network calls and persists
safe validation metadata. Treat those effects separately from response value
safety.

| Tool | Description |
|------|-------------|
| `phantom_capability` | Report the conversation facade's authority and hard denials; advanced compatibility tools are separately gated. |
| `phantom_do` | Propose one closed Cargo action and return its canonical digest/effect/blockers. It never executes today. |
| `phantom_setup_workspace` | Propose value-blind setup, request trusted-terminal apply, or read authenticated status. First proposal may provision a reported machine-local key; MCP never applies. |
| `phantom_list_secrets` | List all secret names in the vault. Returns names only. |
| `phantom_status` | Show project status: vault backend, secret count, service mappings, proxy state. |
| `phantom_doctor` | Diagnose configuration and vault health. |
| `phantom_why` | Explain why a key is or is not classified as a secret. |
| `phantom_check` | Scan the repo for unprotected secrets (pre-commit-style). |
| `phantom_env` | Generate `.env.example` with secrets replaced by placeholders. |
| `phantom_sync` | Preview deployment-platform sync (Vercel, Railway). |
| `phantom_cloud_status` | Check cloud authentication and sync status. |
| `phantom_validate_secret` | Show last-known validation status for one secret. |
| `phantom_validate_all` | Run live credential health checks and persist safe validation metadata. |
| `phantom_validation_schedule` / `phantom_validation_history` | Inspect validation cadence and run history. |

**Mutating (modify the vault or `.env`):**

| Tool | Description |
|------|-------------|
| `phantom_init` | Initialize Phantom in a project. Stores real secrets in the keychain vault and rewrites `.env` with phantom tokens. |
| `phantom_add_secret_interactive` | Start a trusted terminal prompt for adding a new secret without passing the value through MCP. |
| `phantom_add_secret` | Deprecated compatibility tool; refuses plaintext values passed through MCP. |
| `phantom_remove_secret` | Remove a secret from the vault by name. |
| `phantom_rotate` | Regenerate all phantom tokens. Old tokens become invalid; real secrets unchanged. |
| `phantom_copy_secret` | Copy a secret from this project to another project's vault. |
| `phantom_wrap` | Wrap `package.json` scripts with `npx phantom-secrets exec` so npm scripts run through the proxy and get real credentials at runtime. Originals are saved as `script:raw` variants. |
| `phantom_unwrap` | Reverse `phantom_wrap`: restore original `package.json` scripts from `:raw` variants and remove the `:raw` entries. |
| `phantom_cloud_push` | Push encrypted vault to Phantom Cloud (E2E encrypted). |
| `phantom_cloud_pull` | Pull and decrypt vault from Phantom Cloud. |
| `phantom_rotate_with_candidate` / `phantom_rotate_promote` | Stage and promote credential rotation candidates without exposing values. |
| `phantom_rotate_provider` | Rotate through a configured vendor provider such as Stripe, GitHub, or AWS. |
| `phantom_rotate_with_expiry` / `phantom_secrets_auto_rotate` | Refresh phantom tokens and expiry metadata. |

**Team vaults (Pro plan; multi-developer shared vaults with envelope encryption):**

| Tool | Description |
|------|-------------|
| `phantom_team_list` | List teams the authenticated user belongs to. (Read-only.) |
| `phantom_team_create` | Create a new team. Caller becomes owner. (Mutating, requires `confirm`.) |
| `phantom_team_members` | List members of a team. (Read-only.) |
| `phantom_team_invite` | Invite someone to a team by GitHub username. (Mutating, requires `confirm`.) |
| `phantom_team_key_publish` | Register the caller's X25519 public key on a team. Idempotent. |
| `phantom_team_vault_push` | Push the current project's vault to a team. Encrypts the vault with a fresh symmetric key, then wraps that key (X25519 + ChaCha20-Poly1305) for every member with a registered public key. (Mutating, requires `confirm`.) |
| `phantom_team_vault_pull` | Pull the current project's team vault, decrypt the key share with the OS-keychain private key, decrypt the vault, write into the local vault. (Mutating, requires `confirm`.) |

**Audit, compliance, rotation, and expiry:**

| Tool | Description |
|------|-------------|
| `phantom_audit_recent` / `phantom_audit_stats` / `phantom_audit_analytics` | Read recent audit events and aggregate analytics without secret values. |
| `phantom_audit_anomalies` / `phantom_audit_anomalies_realtime` / `phantom_audit_hotspot_alerts` | Detect suspicious access patterns and access-velocity alerts. |
| `phantom_audit_incidents` / `phantom_leak_incidents_realtime` / `phantom_audit_alerts` | Review leak incidents and alert records without exposing credentials. |
| `phantom_audit_export_report` / `phantom_compliance_status` | Export audit data and report compliance readiness. |
| `phantom_secret_rotation_due` / `phantom_list_with_expiry` / `phantom_secrets_expiry_check` | Inspect rotation and expiry status. |
| `phantom_expiry_enforce` / `phantom_rotation_schedule_next` / `phantom_apply_expiry_policy` | Enforce expiry policy and inspect scheduled rotation state. |

## Architecture

- **Binary**: `phantom-mcp` (Rust, compiled native binary)
- **MCP SDK**: [rmcp](https://crates.io/crates/rmcp) v1.x (Rust MCP SDK)
- **Transport**: stdio (JSON-RPC over stdin/stdout)
- **Vault backend**: OS keychain (macOS Keychain, Linux Secret Service, Windows Credential Manager)
- **Local-first storage**: Core vault storage is local. Cloud sync, provider validation/rotation, team workflows, and deployment sync are explicit network operations.

## Installation

### From npm (recommended)

```bash
npm install -g phantom-secrets-mcp
```

This installs a thin Node.js wrapper that downloads the correct native binary for your platform on first run.

### From source

```bash
git clone https://github.com/ashlrai/phantom-secrets.git
cd phantom-secrets
cargo build --release -p phantom-secrets-mcp --bin phantom-mcp
# Binary at target/release/phantom-mcp
```

### From GitHub releases

Download the `phantom-mcp` binary for your platform from [GitHub Releases](https://github.com/ashlrai/phantom-secrets/releases) and place it on your PATH.

## Configuration

Add to your MCP client configuration (e.g., Claude Desktop `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "phantom-secrets": {
      "command": "phantom-mcp",
      "args": [],
      "transport": "stdio"
    }
  }
}
```

Or if installed via npm:

```json
{
  "mcpServers": {
    "phantom-secrets": {
      "command": "npx",
      "args": ["-y", "phantom-secrets-mcp"],
      "transport": "stdio"
    }
  }
}
```

## How phantom tokens work

For agent-led onboarding, call `phantom_capability` first and then
`phantom_setup_workspace`. Its default `propose` phase returns a value-blind,
exact sealed plan. `request_apply` recomputes the supplied plan and pre-state
digests before creating a bearerless pending request; `status` reads its
authenticated workspace-scoped state. MCP cannot claim or apply a request and
receives no bearer or approval token. The first proposal may provision the
machine-local plan-seal key; machine-local Phantom state is checked or hardened,
and the response reports `plan_seal_key_provisioned`. Run `phantom workspace apply --request
<ID>` only in an attached trusted terminal. The related CLI commands are
`phantom workspace plan [--json]`, `phantom workspace apply --request <ID>`,
and `phantom workspace status --request <ID> [--json]`.

1. You run `phantom_init` (or `phantom init` from the CLI) in a project with a `.env` file.
2. Real secrets like `OPENAI_API_KEY=sk-abc123...` are moved into the OS keychain vault.
3. The `.env` file is rewritten: `OPENAI_API_KEY=phm_a1b2c3d4e5f6...`
4. Phantom does not grant agents dotenv read access. Agents inspect names and protection state through value-blind MCP tools; application processes load phantom tokens for authenticated proxy sessions.
5. When your app runs under the Phantom proxy (`phantom exec -- npm start`), HTTP requests containing phantom tokens are intercepted and the real secret is substituted at the network layer.

## Security model

- **MCP responses are value-blind.** Phantom MCP returns names and safe metadata, not stored credential values. Other tools, process access, and pasted values remain outside this claim.
- **Phantom tokens are cryptographically random** and carry no information about the real secret.
- **OS keychain storage** uses platform-native encryption (macOS Keychain, GNOME Keyring / KWallet, Windows DPAPI).
- **Token rotation** (`phantom_rotate`) invalidates all existing tokens without changing vault contents.

## MCP Registry submission

This directory contains the files needed to publish to the [MCP Registry](https://registry.modelcontextprotocol.io/):

- `server.json` — Server metadata for the registry.
- `README.md` — This file.

### Prerequisites before publishing

1. **Verify the npm package**: The registry manifest may refer only to an exact
   `phantom-secrets-mcp` version that is already published and independently
   verified. The local wrapper source or this README is not proof that a
   package or matching native archive has been published. Its `package.json`
   must include:
   ```json
   {
     "name": "phantom-secrets-mcp",
     "mcpName": "io.github.ashlrai/phantom-secrets-mcp"
   }
   ```

2. **Install mcp-publisher**:
   ```bash
   brew install mcp-publisher
   ```

3. **Authenticate**:
   ```bash
   mcp-publisher login github
   ```

4. **Publish only with separate authorization**:
   ```bash
   cd mcp-registry
   mcp-publisher publish
   ```

These commands describe an operator workflow; they do not indicate that npm or
MCP Registry publication, signing, or native acceptance has occurred.

## License

MIT
