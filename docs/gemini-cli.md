# Phantom + Gemini CLI

## Why this combination exists

Gemini CLI reads files in your project and runs shell commands for you. A
`.env` file that holds real API keys is visible to it, so those values can
reach the model, its transcript, or a command line.

After `phantom init`, successfully managed dotenv entries hold phantom tokens
(`phm_...`). Gemini CLI reads the tokens, not the real values. For a supported
outbound API call, the authenticated proxy matches an exact route and injects
only its route-owned vault value into the fixed auth header. Client-controlled
headers and bodies never resolve tokens.

The MCP integration gives Gemini CLI the same tool catalog as every other MCP
client. The runtime `tools/list` response and
[`mcp-registry/server.json`](../mcp-registry/server.json) are canonical.

---

## Install

### Step 1: install Phantom

Install the release binaries using the platform-specific, checksum-verified
path in [getting started](./getting-started.md#install), then run
`phantom init` in the project.

### Step 2: wire up Gemini CLI (one command)

```bash
phantom setup --client gemini
```

`gemini-cli` is accepted as an alias for `gemini`. Setup merges a `phantom`
entry into the top-level `mcpServers` object of `~/.gemini/settings.json` and
leaves your other settings and servers alone. A typical bundled-runtime entry
looks like this; setup supplies the actual absolute path:

```json
{
  "mcpServers": {
    "phantom": {
      "command": "/path/to/phantom",
      "args": ["mcp", "serve"]
    }
  }
}
```

Setup records the running `phantom` executable with `mcp serve` when it can
resolve that runtime, otherwise it looks for a local `phantom-mcp`. It has no
network package-runner fallback and fails closed when neither local runtime is
executable. The file is your user settings, so the entry applies to every
Gemini CLI session.

Preview before you write anything:

```bash
phantom setup --client gemini --print     # the snippet, on stdout
phantom setup --client gemini --dry-run   # the change to ~/.gemini/settings.json, as a diff
```

Setup reads the file as strict JSON. If the file does not parse, or if it
already has a `phantom` entry that differs from what setup would write, setup
stops, names the problem, and changes nothing. Re-run with `--replace` to
overwrite a differing entry; setup writes a backup and a manifest first, and
`phantom setup --undo` shows how to reverse it (`--undo --apply` does it).

After setup, **restart Gemini CLI**. The `/mcp` command inside Gemini CLI lists
the connected servers. To confirm the wiring from a terminal without writing
anything:

```bash
phantom setup --status
```

It reports `wired`, `not_wired`, `no_config`, or `unreadable` for each client,
including Gemini CLI. Add the global `--json` flag for automation.

### Step 3: run with the proxy active

```bash
phantom exec -- gemini
```

This starts an authenticated loopback proxy for the session and launches
Gemini CLI with fresh placeholders in its environment. New projects include a
built-in `google_ai` route that injects `GEMINI_API_KEY` into the
`x-goog-api-key` header for `generativelanguage.googleapis.com`. An exported
`*_BASE_URL` only helps software that reads that variable, and a route existing
for a key does not prove that a particular program sends its requests through
the proxy, so check what a key gets before you rely on it:

```bash
phantom why GEMINI_API_KEY --json
```

`exec.delivery: no_route` means no built-in route injects that key, and the
child only holds a token. [docs/exec.md](./exec.md) describes the child
environment and the proxy routes.

---

## MCP tools Gemini CLI can use

Gemini CLI calls the same runtime catalog as other MCP clients. See the
[core tool examples in the Claude Code guide](./claude-code.md#core-mcp-tools-claude-can-use).
Start with `phantom_capability`. Value-free tools include:

- `phantom_status`: `.env` protection state and service mappings (does not open
  the vault; use `phantom_list_secrets` for stored names)
- `phantom_list_secrets`: secret names, never values
- `phantom_why`: whether a variable is protected and how it is delivered
- `phantom_add_secret_interactive`: returns the `phantom add NAME` command for
  you to run in a trusted terminal

Effectful MCP calls are disabled by default. They require
`PHANTOM_MCP_EFFECTS=trusted-terminal` set outside agent authority,
`confirm: true`, and a one-use approval token from an attached-terminal
`phantom mcp-approve` ceremony outside the agent's shell and PTY authority.

---

## Daily flow

```bash
# Launch Gemini CLI with the proxy running
phantom exec -- gemini

# Add a new API key without typing the value into chat
phantom add GEMINI_API_KEY
# enter the value at the hidden terminal prompt

# Check that everything is configured correctly
phantom doctor
```

---

## Troubleshooting

**Gemini CLI does not list the `phantom` server**

Run `phantom setup --status`. If Gemini CLI shows `not_wired` or `no_config`,
re-run `phantom setup --client gemini`, then restart Gemini CLI; it loads MCP
servers at startup.

**Setup fails to parse `~/.gemini/settings.json`**

Setup accepts only strict JSON and changed nothing. Remove comments or trailing
commas from the file, or add the `--print` snippet to `mcpServers` by hand.

**`phantom setup` says the local MCP runtime is missing**

Setup did not find a runnable bundled server or executable local standalone
server. Install the verified binaries using the platform-specific path in
[getting started](./getting-started.md#install), then re-run
`phantom setup --client gemini`.

**A tool answers "Vault locked: ..."**

The project's secrets are in an encrypted-file vault the MCP server cannot
open, usually because `PHANTOM_VAULT_PASSPHRASE` is not set in the server's
environment. It does not mean the vault is empty. See
[troubleshooting](./troubleshooting.md#vault-locked-this-projects-secrets-are-in-an-encrypted-file-vault-this-process-cannot-open).

---

## Reference

- Full setup guide: [getting-started.md](./getting-started.md)
- Agent setup walkthrough: [agent-quickstart.md](./agent-quickstart.md)
- Troubleshooting: [troubleshooting.md](./troubleshooting.md)
- Site: [https://phm.dev](https://phm.dev)
