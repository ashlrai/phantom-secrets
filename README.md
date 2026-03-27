# Phantom

**Prevent AI coding agents from leaking your API keys.**

Phantom replaces real secrets in your `.env` with worthless phantom tokens. A local proxy intercepts API calls, swaps in real credentials at the network layer. The AI agent never sees a real secret.

## The Problem

AI coding tools (Claude Code, Cursor, Copilot) read `.env` files, putting secrets into LLM context windows where they can leak via prompt injection, malicious MCP servers, session logs, or training data. GitGuardian reports AI-assisted commits leak secrets at **2x the baseline rate**.

## How It Works

```
Before phantom:
  .env contains:  OPENAI_API_KEY=sk-real-secret-key
  AI agent sees:   sk-real-secret-key  (leaked!)

After phantom:
  .env contains:  OPENAI_API_KEY=phm_a7f3b9e2...  (worthless token)
  AI agent sees:   phm_a7f3b9e2...  (safe to leak)
  Proxy injects:  sk-real-secret-key  (at network layer, never in context)
```

## Quick Start

```bash
# Install
cargo install phantom  # or: brew install phantom-secrets/tap/phantom

# In your project
cd my-project
phantom init
# => Found 3 secret(s) to protect: OPENAI_API_KEY, ANTHROPIC_API_KEY, DATABASE_URL
# => Rewrote .env with phantom tokens
# => Saved real secrets to OS keychain

# Code with AI safely
phantom exec -- claude
# => Proxy running on 127.0.0.1:54321
# => AI sees phantom tokens, proxy injects real keys at network layer
```

## Commands

| Command | Description |
|---------|-------------|
| `phantom init` | Import `.env` secrets into vault, rewrite with phantom tokens |
| `phantom exec -- <cmd>` | Start proxy + run command (primary daily-use command) |
| `phantom start` / `stop` | Proxy lifecycle (standalone mode) |
| `phantom list` | Show secret names (never values) |
| `phantom add <KEY> <VALUE>` | Add a secret to the vault |
| `phantom remove <KEY>` | Remove a secret from the vault |
| `phantom status` | Show proxy status and mapped secrets |
| `phantom rotate` | Regenerate phantom tokens |
| `phantom doctor` | Check configuration and vault health |
| `phantom check` | Scan for unprotected secrets (pre-commit hook) |

## Architecture

```
 .env (phantom tokens)        Vault (OS keychain)
 +---------------------+      +-------------------+
 | OPENAI_API_KEY=phm_  | --> | sk-real-key       |
 +---------------------+      +-------------------+
        |                              |
        v                              v
 AI Agent (Claude Code)        Phantom Proxy (127.0.0.1)
 +---------------------+      +----------------------------+
 | Reads .env           |      | Intercepts HTTP requests   |
 | Sees phm_ tokens     | ---> | Replaces phm_ with real    |
 | Makes API calls      |      | Forwards to api.openai.com |
 +---------------------+      +----------------------------+
```

### How the proxy works

1. `phantom init` reads your `.env`, stores real secrets in the OS keychain, rewrites `.env` with `phm_` phantom tokens
2. `phantom exec -- claude` starts a local HTTP proxy and sets `OPENAI_BASE_URL=http://127.0.0.1:PORT/openai` (and similar for other services)
3. When code makes an API call, it hits the local proxy instead of the real API
4. The proxy scans request headers and body for phantom tokens, replaces them with real secrets from the vault
5. The proxy forwards the modified request over TLS to the real API endpoint
6. When the session ends, the proxy shuts down. Phantom tokens are inert outside the proxy.

### What gets protected

Phantom uses heuristics to detect secrets in your `.env`:
- **Key patterns**: `*_API_KEY`, `*_SECRET*`, `*_TOKEN`, `*_PASSWORD`, `DATABASE_URL`, etc.
- **Value patterns**: `sk-*`, `sk_*`, `ghp_*`, `Bearer *`, connection strings with `@`
- **Non-secrets are left untouched**: `NODE_ENV`, `PORT`, `DEBUG`, etc.

### Built-in service patterns

| Service | Env Var | Proxy Route |
|---------|---------|-------------|
| OpenAI | `OPENAI_API_KEY` | `/openai/*` -> `api.openai.com` |
| Anthropic | `ANTHROPIC_API_KEY` | `/anthropic/*` -> `api.anthropic.com` |
| Stripe | `STRIPE_SECRET_KEY` | `/stripe/*` -> `api.stripe.com` |
| Supabase | `SUPABASE_SERVICE_ROLE_KEY` | `/supabase/*` -> `supabase.co` |
| Database | `DATABASE_URL` | Injected as env var (not proxied) |

Custom services can be added in `.phantom.toml`.

## Security Model

- **Real secrets never touch the filesystem** in your project directory — they go from `.env` to the vault on first run, then `.env` is overwritten with phantom tokens
- **Phantom tokens are 256-bit CSPRNG** with `phm_` prefix — never collide with real API key formats
- **Proxy binds to 127.0.0.1 only** — never exposed to the network
- **Secrets are zeroized from memory** after injection into outgoing requests
- **Allowlist model** — the proxy only injects for configured service patterns; unknown hosts receive the phantom token (which simply fails as an invalid key)
- **OS keychain storage** — macOS Keychain (Secure Enclave on Apple Silicon), Linux Secret Service; encrypted file fallback for CI/Docker

See [SECURITY.md](SECURITY.md) for the full threat model.

## Configuration

Phantom creates a `.phantom.toml` in your project root:

```toml
[phantom]
version = "1"
project_id = "a1b2c3d4e5f6g7h8"

[services.openai]
secret_key = "OPENAI_API_KEY"
pattern = "api.openai.com"
header = "Authorization"
header_format = "Bearer {secret}"

[services.custom_api]
secret_key = "MY_CUSTOM_KEY"
pattern = "api.example.com"
header = "X-Api-Key"
header_format = "{secret}"
secret_type = "api_key"
```

## Pre-commit Hook

Phantom includes a pre-commit hook that blocks commits containing unprotected secrets.

### With [pre-commit](https://pre-commit.com/)

Add to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/ashlrai/phantom-secrets
    rev: v0.1.0
    hooks:
      - id: phantom-check
```

### Manual git hook

```bash
# Add to .git/hooks/pre-commit:
#!/bin/sh
phantom check
```

### What it catches

- Real API keys in `.env` files (should be phantom tokens)
- Hardcoded secrets in staged code files (`sk-*`, `ghp_*`, `AKIA*`, etc.)

```
$ phantom check
BLOCKED Unprotected secrets detected!

  ! .env has 1 unprotected secret(s):
    - OPENAI_API_KEY

fix Run phantom init to protect your secrets.
```

## MCP Server (Claude Code Integration)

Phantom includes an MCP server so Claude Code can natively manage secrets without ever seeing real values.

### Setup

Add to your Claude Code MCP config (`.claude/settings.json` or global settings):

```json
{
  "mcpServers": {
    "phantom": {
      "command": "phantom-mcp",
      "args": []
    }
  }
}
```

Or if installed via cargo:

```json
{
  "mcpServers": {
    "phantom": {
      "command": "/path/to/phantom-mcp",
      "args": []
    }
  }
}
```

### Available Tools

| Tool | Description |
|------|-------------|
| `phantom_list_secrets` | List secret names (never shows values) |
| `phantom_status` | Show vault, config, and proxy status |
| `phantom_init` | Initialize Phantom and protect .env secrets |
| `phantom_add_secret` | Add a secret to the vault |
| `phantom_remove_secret` | Remove a secret from the vault |
| `phantom_rotate` | Regenerate all phantom tokens |

Claude Code can call these tools to manage secrets safely — the MCP server ensures no real secret values ever enter the AI's context window.

## Development

```bash
# Build
cargo build

# Run tests
cargo test

# Run with verbose logging
cargo run -- --verbose exec -- echo "test"

# Test MCP server (stdio)
cargo run --bin phantom-mcp
```

## License

MIT - see [LICENSE](LICENSE)
