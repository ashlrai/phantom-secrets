# Phantom + Codex

## Why this combination exists

OpenAI Codex runs in a sandboxed environment and executes tasks autonomously. It reads files in your repository — including `.env` — to understand the project. Real API keys in `.env` would be visible to the agent and present in its working context throughout the task.

After `phantom init`, your `.env` contains only phantom tokens (`phm_...`). Codex reads the tokens, not the real values. When code under test makes API calls, the local Phantom proxy replaces tokens with real credentials before requests leave your machine — Codex never needs the real values to write, test, or integrate code that uses them.

The MCP integration registers 25 Phantom tools in Codex's tool list. The CLI has 34 commands including `phantom audit show/tail/path/verify`, `phantom import --from`, and `phantom export --json`.

---

## Install

### Step 1: install Phantom

```bash
npx phantom-secrets init
```

This installs the CLI and initializes your current project in one step.

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

If `phantom-mcp` is not on PATH, the command falls back to `npx -y phantom-secrets-mcp`.

To preview the snippet without modifying your config:

```bash
phantom setup --client codex --print
```

After running setup, **restart Codex** for the MCP server to activate.

### Step 3: run Codex tasks with the proxy active

```bash
phantom exec -- codex "add Stripe checkout to checkout.ts"
```

This starts the Phantom proxy, sets `*_BASE_URL` environment variables, then hands off to Codex. Any API calls Codex makes while testing or executing code flow through the proxy.

For interactive sessions or repeated Codex runs, start the proxy once and leave it running:

```bash
phantom start
codex "refactor auth module"
codex "add tests for payment flow"
phantom stop
```

---

## The 25 MCP tools Codex gets

Once `phantom-secrets-mcp` is registered, Codex can call all 25 Phantom tools during task execution. See the complete table in [claude-code.md](./claude-code.md#the-25-mcp-tools-claude-gets) — the tool set is identical across all AI clients.

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

Codex writes code that references `process.env.RESEND_API_KEY` (or equivalent). That variable holds `phm_...` in the environment. When Codex executes a test call, the proxy swaps the token for the real key. The generated code is correct and works in production without modification.

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
