# Phantom + Windsurf

## Why this combination exists

Windsurf's Cascade AI reads files in your workspace to understand context. A `.env` file containing real API keys is visible to Cascade and can surface in suggestions, explanations, and generated code.

After `phantom init`, successfully managed dotenv entries hold phantom tokens (`phm_...`). Cascade reads the tokens, not the real values. For a supported outbound API call, the authenticated proxy matches an exact route and injects only its route-owned vault value into the fixed auth header. Client-controlled headers and bodies never resolve tokens.

The MCP integration exposes the release-schema-verified catalog in Windsurf's
Cascade chat. The current release contract enforces 54 unique tools; runtime
`tools/list` is canonical.

---

## Install

### Step 1: install Phantom

Install the reviewed `v0.7.8` binary using the platform-specific, checksum-
verified path in [getting started](./getting-started.md#install), then run
`phantom init` in the project.

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

Install both `v0.7.8` release binaries before setup. Version `0.7.8` records the
running `phantom` executable with `mcp serve` when it can resolve that runtime,
otherwise it looks for a local `phantom-mcp`. Setup has no network
package-runner fallback and fails closed when neither local runtime is
executable. Keep both verified binaries installed and inspect the generated
entry. The config is global and applies to every Windsurf
workspace.

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

For an explicitly supervised longer session, run `phantom start` in a trusted
terminal and keep it open. Copy the printed exports into the terminal that
launches Windsurf, then press Ctrl-C in the original owning terminal to stop.
Detached `--daemon` mode and current external process control fail closed;
`phantom stop` authenticates legacy v0.7.3 state only to report manual
migration guidance and never kills a process or deletes the record.

---

## MCP tools Windsurf can use

Once `phantom-secrets-mcp` is registered, Cascade can call the same runtime
catalog as other MCP clients. See the [core tool examples in the Claude Code
guide](./claude-code.md#core-mcp-tools-claude-can-use), and use MCP `tools/list`
for the canonical catalog.

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

Inside a session started with `phantom exec`, your application code runs normally. `process.env.MY_KEY` may hold a `phm_...` token, while an exact supported proxy route injects its own configured vault value into the upstream auth header. The token itself is never swapped in a client header or body.

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

**`phantom setup` says the local MCP runtime is missing**

On current main, this means setup did not find a runnable bundled server or
executable local standalone server. Install both verified binaries using the
platform-specific path in [getting started](./getting-started.md#install), then
re-run `phantom setup --client windsurf`. Released `v0.7.8` fails closed instead
of generating a registry-backed command.

---

## Reference

- Full setup guide: [getting-started.md](./getting-started.md)
- Troubleshooting: [troubleshooting.md](./troubleshooting.md)
- Sync to Vercel / Railway: [sync.md](./sync.md)
- Cloud login: [login.md](./login.md)
- Site: [https://phm.dev](https://phm.dev)
