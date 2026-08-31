# Phantom + Cursor

## Why this combination exists

Cursor indexes your project files to power its AI completions and chat context. If your `.env` contains real API keys, those values flow directly into Cursor's context window and can appear in completions, inline suggestions, and chat transcripts.

After `phantom init`, managed dotenv secrets are replaced by `phm_` tokens.
Those values are not accepted by providers, but they remain sensitive mappings
until rotation. When supported API code runs in a Cursor process launched by
`phantom exec`, the authenticated local proxy replaces a session token on a
reviewed route and sends the real value to the configured provider over TLS.
Unmanaged files, unsupported protocols, and processes outside that environment
remain outside this boundary.

The MCP integration exposes the release-schema-verified catalog in Cursor Chat,
so you can manage secrets without leaving the editor. The current release
contract enforces 54 unique tools; runtime `tools/list` is canonical.

---

## Install

### Step 1: install Phantom

Install the reviewed `v0.7.3` binary using the platform-specific, checksum-
verified path in [getting started](./getting-started.md#install), then run
`phantom init` in the project.

### Step 2: wire up Cursor (one command)

```bash
phantom setup --client cursor
```

This writes `~/.cursor/mcp.json` with the `phantom` MCP server entry:

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

Install both `v0.7.3` release binaries before setup. Setup normally records the
installed `phantom` executable with `mcp serve`. Its standalone fallback accepts
only an executable local `phantom-mcp`: first on `PATH`, then beside `phantom`
(`phantom-mcp.exe` on Windows), then in `~/.cargo/bin`. If none is available,
setup fails closed with verified `v0.7.3` install guidance; it never downloads
or executes an unpinned registry package. The config is global and applies to
every Cursor workspace.

To see what would be written without modifying your config:

```bash
phantom setup --client cursor --print
```

After running setup, **restart Cursor** for the MCP server to activate.

### Step 3: run Cursor terminal sessions with the proxy active

```bash
phantom exec -- cursor .
```

This starts the Phantom proxy on `127.0.0.1`, sets `*_BASE_URL` environment variables for supported services (OpenAI, Anthropic, etc.), then launches Cursor. API calls made from Cursor's integrated terminal go through the proxy.

Alternatively, start the proxy in the background and keep it running across sessions:

```bash
phantom start
# ... work in Cursor normally ...
phantom stop
```

---

## MCP tools Cursor can use

Once `phantom-secrets-mcp` is registered, Cursor Chat can call the same runtime
catalog as other MCP clients. See the [core tool examples in the Claude Code
guide](./claude-code.md#core-mcp-tools-claude-can-use), and use MCP `tools/list`
for the canonical catalog.

Key tools for Cursor users:

- `phantom_status` — check vault health and service mappings before starting work
- `phantom_list_secrets` — see which secrets are loaded (names only, never values)
- `phantom_add_secret_interactive` — start the terminal-based secret entry flow
- `phantom_doctor` — validate config, `.gitignore`, `.env.example`, and pre-commit hook
- `phantom_cloud_push` / `phantom_cloud_pull` — sync vault to/from Phantom Cloud

---

## Daily flow

```bash
# Start a session with secrets available in the proxy
phantom exec -- cursor .

# Add a new secret without exposing the value in chat
phantom add STRIPE_SECRET_KEY
# enter value at the terminal prompt

# Verify the vault is healthy
phantom doctor

# Push updated vault to cloud so teammates can pull
phantom cloud push
```

Within a Cursor terminal session running under `phantom exec`, your existing code runs unmodified — `process.env.OPENAI_API_KEY` resolves to `phm_...` in the process environment, but the proxy replaces it with the real key before the HTTP request is sent.

---

## Troubleshooting

**MCP tools not showing up in Cursor Chat**

Check that `~/.cursor/mcp.json` exists and contains the `phantom` entry:

```bash
cat ~/.cursor/mcp.json
```

If it looks correct, restart Cursor. Cursor reads MCP config on startup only. If
setup reports that the local MCP runtime is missing, reinstall both binaries
from the reviewed `v0.7.3` release. Setup fails closed instead of generating a
registry-backed command.

**`phantom exec -- cursor .` opens Cursor but API calls fail**

The proxy sets `*_BASE_URL` variables only in the shell environment `phantom exec` inherits from. If Cursor is already running as a background app (e.g., opened via the dock), those variables are not set. Close any existing Cursor windows and launch only from the `phantom exec` command.

**Cursor AI sees `phm_...` tokens in code completions**

Managed dotenv files contain project `phm_` mappings, but those mappings should
not be copied into source or intentionally committed. If a token appears in a
completion, remove it from generated code and rotate it with `phantom rotate`;
an authenticated active Phantom proxy is the component that can resolve it.

---

## Reference

- Full setup guide: [getting-started.md](./getting-started.md)
- Troubleshooting: [troubleshooting.md](./troubleshooting.md)
- Sync to Vercel / Railway: [sync.md](./sync.md)
- Cloud login: [login.md](./login.md)
- Site: [https://phm.dev](https://phm.dev)
