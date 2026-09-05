# Phantom + Cursor

## Why this combination exists

Cursor indexes your project files to power its AI completions and chat context. If your `.env` contains real API keys, those values flow directly into Cursor's context window and can appear in completions, inline suggestions, and chat transcripts.

After `phantom init`, managed dotenv secrets are replaced by `phm_` tokens.
Those values are not accepted by providers, but they remain sensitive mappings
until rotation. When supported API code runs in a Cursor process launched by
`phantom exec`, the authenticated local proxy matches an exact reviewed route,
discards client control of its auth header, and injects only the route-owned
vault value there before sending the request over TLS. Client headers and bodies
never resolve session tokens.
Unmanaged files, unsupported protocols, and processes outside that environment
remain outside this boundary.

The MCP integration exposes the release-schema-verified catalog in Cursor Chat,
so you can manage secrets without leaving the editor. The current release
contract enforces 54 unique tools; runtime `tools/list` is canonical.

---

## Install

### Step 1: install Phantom

Install the reviewed `v0.7.8` binary using the platform-specific, checksum-
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

Install both `v0.7.8` release binaries before setup. Version `0.7.8` records the
running `phantom` executable with `mcp serve` when it can resolve that runtime,
otherwise it looks for a local `phantom-mcp`. Setup has no network
package-runner fallback and fails closed when neither local runtime is
executable. Keep both verified binaries installed and inspect the generated
entry. The config is global and applies to every Cursor
workspace.

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

For an explicitly supervised shared session, run `phantom start` in a trusted
terminal and keep it open. Copy the printed exports into the terminal that
launches Cursor, then press Ctrl-C in the original owning terminal to stop.
Detached `--daemon` mode and current external process control fail closed;
`phantom stop` authenticates legacy v0.7.3 state only to report manual
migration guidance and never kills or deletes. Prefer
`phantom exec -- cursor .` when one child process is sufficient.

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
- `phantom_cloud_push` / `phantom_cloud_pull` — dual-gated cloud effects. With
  `force=false`, a partial pull blocks push until full reconciliation.

Effectful MCP calls require `confirm: true` plus a one-use `approval_token`
created through an attached-terminal `phantom mcp-approve` ceremony outside
Cursor's shell and PTY authority. The same gates apply to authenticated
provider reads such as cloud status and team list/members.

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

# After separately verified hosted commissioning and entitlement, request an
# encrypted cloud push. The public hosted service is not currently commissioned.
phantom cloud push
```

Within a Cursor terminal session running under `phantom exec`, your existing code runs unmodified — `process.env.OPENAI_API_KEY` holds `phm_...`, while the exact OpenAI proxy route injects its configured vault value into the upstream auth header. No client-controlled header or body is substituted.

---

## Troubleshooting

**MCP tools not showing up in Cursor Chat**

Check that `~/.cursor/mcp.json` exists and contains the `phantom` entry:

```bash
cat ~/.cursor/mcp.json
```

If it looks correct, restart Cursor. Cursor reads MCP config on startup only. If
setup reports that the local MCP runtime is missing, reinstall both verified
`v0.7.8` binaries. The released setup path fails closed instead of generating a
registry-backed command.

**`phantom exec -- cursor .` opens Cursor but API calls fail**

The proxy sets `*_BASE_URL` variables only in the shell environment `phantom exec` inherits from. If Cursor is already running as a background app (e.g., opened via the dock), those variables are not set. Close any existing Cursor windows and launch only from the `phantom exec` command.

**Cursor AI sees `phm_...` tokens in code completions**

Managed dotenv files contain project `phm_` mappings, but those mappings should
not be copied into source or intentionally committed. If a token appears in a
completion, remove it from generated code and rotate it with `phantom rotate`;
client headers and bodies never resolve it. A stolen live proxy bearer can
still authorize exact configured routes that inject their own credentials.

---

## Reference

- Full setup guide: [getting-started.md](./getting-started.md)
- Troubleshooting: [troubleshooting.md](./troubleshooting.md)
- Sync to Vercel / Railway: [sync.md](./sync.md)
- Cloud login: [login.md](./login.md)
- Site: [https://phm.dev](https://phm.dev)
