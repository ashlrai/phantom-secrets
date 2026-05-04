# Phantom + Windsurf

## Why this combination exists

Windsurf's Cascade AI reads files in your workspace to understand context. A `.env` file containing real API keys is visible to Cascade and can surface in suggestions, explanations, and generated code.

After `phantom init`, your `.env` holds only phantom tokens (`phm_...`). Cascade reads the tokens, not the real values. When your code makes an outbound API call during development, the local Phantom proxy replaces the token with the real value before the request leaves your machine.

The MCP integration registers 25 tools in Windsurf, accessible from Cascade chat.

---

## Install

### Step 1: install Phantom

```bash
npx phantom-secrets init
```

This installs the CLI and initializes your current project in one step.

### Step 2: wire up Windsurf (one command)

```bash
phantom setup --client windsurf
```

This writes `~/.codeium/windsurf/mcp_config.json` with the `phantom` MCP server entry:

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

If `phantom-mcp` is not on PATH, the command falls back to `npx -y phantom-secrets-mcp`. The config is global — it applies to every Windsurf workspace.

To preview what would be written without modifying the file:

```bash
phantom setup --client windsurf --print
```

After running setup, **restart Windsurf** for the MCP server to activate.

### Step 3: run Windsurf with the proxy active

```bash
phantom exec -- windsurf .
```

This starts the Phantom proxy, sets `*_BASE_URL` environment variables, then launches Windsurf. API calls from the integrated terminal flow through the proxy.

For longer-running sessions, use the background proxy instead:

```bash
phantom start
# ... work in Windsurf ...
phantom stop
```

---

## The 25 MCP tools Windsurf gets

Once `phantom-secrets-mcp` is registered, Cascade can call all 25 Phantom tools. See the full table in [claude-code.md](./claude-code.md#the-25-mcp-tools-claude-gets) — the tool set is identical across all supported AI clients.

Frequently used tools in Windsurf sessions:

- `phantom_status` — verify vault backend, secret count, and `.env` protection state
- `phantom_list_secrets` — list secret names (values never returned)
- `phantom_add_secret_interactive` — returns the terminal command to enter a new secret out-of-band
- `phantom_doctor` — run all health checks; pass `fix=true` to auto-repair safe issues
- `phantom_sync` — show which secrets and platforms are configured for deployment sync

---

## Daily flow

```bash
# Launch Windsurf with the proxy running
phantom exec -- windsurf .

# Add a new API key without typing the value into chat
phantom add SENDGRID_API_KEY
# enter value at the terminal prompt

# Check that everything is configured correctly
phantom doctor

# Sync secrets to your deployment platform
phantom sync --platform vercel --project prj_abc123
```

Inside a session started with `phantom exec`, your application code runs normally. The `phm_...` token in `process.env.MY_KEY` is swapped for the real value by the proxy before HTTP requests are made.

---

## Troubleshooting

**Cascade reports it cannot find the MCP tools**

Verify the config file exists:

```bash
cat ~/.codeium/windsurf/mcp_config.json
```

If the file is missing, re-run `phantom setup --client windsurf`. If the file is correct, restart Windsurf — MCP servers are loaded at startup.

**The proxy environment is not passed to the Windsurf terminal**

`phantom exec` sets environment variables in the shell that spawns Windsurf. If Windsurf was already running before you ran `phantom exec`, new terminal tabs inherit the original environment, not the proxy environment. Quit Windsurf completely and relaunch via `phantom exec -- windsurf .`.

**`phantom setup` writes `npx` as the command instead of `phantom-mcp`**

This means `phantom-mcp` was not found on PATH at setup time. The `npx` fallback is functional but adds startup latency on the first call. To switch to the binary, install it (`npm install -g phantom-secrets-mcp` or the Rust install path), then re-run `phantom setup --client windsurf`.

---

## Reference

- Full setup guide: [getting-started.md](./getting-started.md)
- Troubleshooting: [troubleshooting.md](./troubleshooting.md)
- Sync to Vercel / Railway: [sync.md](./sync.md)
- Cloud login: [login.md](./login.md)
- Site: [https://phm.dev](https://phm.dev)
