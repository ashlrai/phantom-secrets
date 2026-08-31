# Phantom + Codex

## Why this combination exists

OpenAI Codex runs in a sandboxed environment and executes tasks autonomously. It reads files in your repository — including `.env` — to understand the project. Real API keys in `.env` would be visible to the agent and present in its working context throughout the task.

After `phantom init`, managed dotenv secrets are replaced by `phm_` tokens, so
Codex can use value-blind metadata instead of real values. For supported HTTP
API routes in a process launched by `phantom exec`, the authenticated local
proxy replaces a fresh session token before the request reaches the configured
provider. Connection strings and unsupported protocols fail closed or require
a separately approved workflow; unmanaged files remain outside this boundary.

The MCP integration registers Phantom's release-schema-verified catalog in
Codex. The current release contract enforces 54 unique tools; runtime
`tools/list` is canonical. The CLI includes agent readiness, proxy lifecycle,
audit, import/export, cloud sync, team vaults, and safe MCP setup for Codex.

---

## Install

### Step 1: install Phantom

Install the reviewed `v0.7.3` binary using the platform-specific, checksum-
verified path in [getting started](./getting-started.md#install), then run
`phantom init` in the project.

### Step 2: wire up Codex (one command)

```bash
phantom setup --client codex
```

This patches `~/.codex/config.toml` with an `[mcp_servers.phantom]` entry:

```toml
[mcp_servers.phantom]
command = "phantom-mcp"
args = []
```

Install both `v0.7.3` release binaries before setup. Setup normally records the
installed `phantom` executable with `mcp serve`. Its standalone fallback accepts
only an executable local `phantom-mcp`: first on `PATH`, then beside `phantom`
(`phantom-mcp.exe` on Windows), then in `~/.cargo/bin`. If none is available,
setup fails closed with verified `v0.7.3` install guidance; it never downloads
or executes an unpinned registry package.

To preview the snippet without modifying your config:

```bash
phantom setup --client codex --print
```

After running setup, **restart Codex** for the MCP server to activate.

### Step 3: verify agent readiness

```bash
phantom agent doctor
phantom agent report --json
```

`phantom agent doctor` is the human-readable preflight for Codex. It checks that env files are phantomized, the vault is available, MCP is wired, package scripts and pre-commit protection are in good shape, and cloud/team/sync state is visible. The JSON report returns `unsafe`, `protected`, `verified`, `team-ready`, or `compliance-ready` for automation.

### Step 4: run Codex tasks with the proxy active

```bash
phantom exec -- codex "add Stripe checkout to checkout.ts"
```

This starts the Phantom proxy, sets the implemented `*_BASE_URL` overrides,
then hands off to Codex. Calls made by SDKs that honor those overrides use the
proxy; arbitrary network clients and unsupported protocols do not.

For interactive sessions or repeated Codex runs, start the proxy once and leave it running:

```bash
phantom start
codex "refactor auth module"
codex "add tests for payment flow"
phantom stop
```

---

## MCP tools Codex can use

Once `phantom-secrets-mcp` is registered, Codex can call the same runtime
catalog as other MCP clients. See the [core tool examples in the Claude Code
guide](./claude-code.md#core-mcp-tools-claude-can-use), and use MCP `tools/list`
for the canonical catalog.

Tools most relevant to Codex task execution:

- `phantom_status` — check vault state before a task starts
- `phantom_list_secrets` — let Codex know which secrets exist without exposing values
- `phantom_add_secret_interactive` — return the terminal command to enter a secret out-of-band; useful when Codex identifies a missing key mid-task
- `phantom_check` — scan `.env` or runtime environment for unprotected secrets
- `phantom_doctor` — validate the full setup; Codex can call this as a pre-task health check

Codex cannot retrieve real secret values through MCP. `phantom_list_secrets` returns names only, and there is no tool that returns a plaintext credential.

---

## Daily flow

```bash
# Run a Codex task with the proxy active
phantom exec -- codex "integrate the Resend email API"

# Codex discovers RESEND_API_KEY is missing — add it out-of-band
phantom add RESEND_API_KEY
# enter value at the terminal prompt

# Re-run the task; the proxy injects the key for any test calls
phantom exec -- codex "finish the Resend integration"

# Push the updated vault to cloud
phantom cloud push
```

Codex writes code that references `process.env.RESEND_API_KEY` (or equivalent).
Under `phantom exec`, that variable holds a fresh-session `phm_...` token. For a
supported HTTP SDK route, the local proxy can swap that token when Codex makes a
test call. The generated environment-variable lookup can remain unchanged, but
the production runtime must be provisioned separately with the corresponding
credential or an approved secret-manager integration. Phantom's local proxy
does not deploy or authorize production credentials.

---

## Troubleshooting

**Codex does not list Phantom in its available tools**

Check that `~/.codex/config.toml` contains the `[mcp_servers.phantom]` block:

```bash
cat ~/.codex/config.toml
```

If missing, re-run `phantom setup --client codex`. If present, restart Codex — MCP servers are read at startup.

**Phantom proxy not active during Codex task execution**

Codex tasks must be launched from a shell where `phantom exec` has set the proxy environment. Launching Codex from a GUI shortcut or a separate terminal bypasses the proxy. Always use `phantom exec -- codex <task>` or confirm `phantom start` has been run in the current shell session.

**Token in `.env` is not being replaced during test calls**

The proxy only intercepts requests sent to URLs that match configured service mappings (`OPENAI_BASE_URL`, `ANTHROPIC_BASE_URL`, etc.). If your code uses a hardcoded URL rather than the `*_BASE_URL` environment variable, it bypasses the proxy. Check `phantom status` to see which service URLs are rewritten, and update your code to use the env var.

---

## Reference

- Full setup guide: [getting-started.md](./getting-started.md)
- Troubleshooting: [troubleshooting.md](./troubleshooting.md)
- Sync to Vercel / Railway: [sync.md](./sync.md)
- Cloud login: [login.md](./login.md)
- Site: [https://phm.dev](https://phm.dev)
