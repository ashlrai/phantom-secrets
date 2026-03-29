# Phantom Secrets MCP Server

<!-- mcp-name: io.github.ashlrai/phantom-secrets-mcp -->

An MCP (Model Context Protocol) server that prevents AI coding agents from leaking your API keys and secrets.

## What it does

Phantom Secrets replaces real secrets in `.env` files with opaque **phantom tokens** (`phm_...`). The AI agent only ever sees these worthless tokens. When your code makes an API call, a local proxy swaps the phantom token for the real credential at the network layer.

The MCP server lets AI agents manage this workflow directly, without ever being exposed to actual secret values.

## Tools

The server exposes 6 tools over MCP stdio transport:

| Tool | Description |
|------|-------------|
| `phantom_list_secrets` | List all secret names in the vault. Returns names only — never exposes actual values. |
| `phantom_status` | Show project status: vault backend, secret count, service mappings, and proxy state. |
| `phantom_init` | Initialize Phantom in a project directory. Reads `.env`, stores real secrets in the OS keychain vault, and rewrites `.env` with phantom tokens. |
| `phantom_add_secret` | Add a new secret to the vault. The value is stored securely and a phantom token is written to `.env`. |
| `phantom_remove_secret` | Remove a secret from the vault by name. |
| `phantom_rotate` | Regenerate all phantom tokens in `.env`. Old tokens become invalid. Real secrets in the vault are unchanged. |

## Architecture

- **Binary**: `phantom-mcp` (Rust, compiled native binary)
- **MCP SDK**: [rmcp](https://crates.io/crates/rmcp) v1.x (Rust MCP SDK)
- **Transport**: stdio (JSON-RPC over stdin/stdout)
- **Vault backend**: OS keychain (macOS Keychain, Linux Secret Service, Windows Credential Manager)
- **No network required**: All secret storage is local. The MCP server never transmits secrets over the network.

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
cargo build --release -p phantom-mcp
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
      "args": ["phantom-secrets-mcp"],
      "transport": "stdio"
    }
  }
}
```

## How phantom tokens work

1. You run `phantom_init` (or `phantom init` from the CLI) in a project with a `.env` file.
2. Real secrets like `OPENAI_API_KEY=sk-abc123...` are moved into the OS keychain vault.
3. The `.env` file is rewritten: `OPENAI_API_KEY=phm_a1b2c3d4e5f6...`
4. AI agents read `.env` and see only phantom tokens. They cannot extract real values.
5. When your app runs under the Phantom proxy (`phantom exec -- npm start`), HTTP requests containing phantom tokens are intercepted and the real secret is substituted at the network layer.

## Security model

- **Secrets never appear in agent context.** The MCP server returns names only, never values.
- **Phantom tokens are cryptographically random** and carry no information about the real secret.
- **OS keychain storage** uses platform-native encryption (macOS Keychain, GNOME Keyring / KWallet, Windows DPAPI).
- **Token rotation** (`phantom_rotate`) invalidates all existing tokens without changing vault contents.

## MCP Registry submission

This directory contains the files needed to publish to the [MCP Registry](https://registry.modelcontextprotocol.io/):

- `server.json` — Server metadata for the registry.
- `README.md` — This file.

### Prerequisites before publishing

1. **Publish the npm package**: Create and publish `phantom-secrets-mcp` on npm. This should be a thin wrapper (like the existing `phantom-secrets` CLI package) that downloads the `phantom-mcp` binary from GitHub releases. The `package.json` must include:
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

4. **Publish**:
   ```bash
   cd mcp-registry
   mcp-publisher publish
   ```

## License

MIT
