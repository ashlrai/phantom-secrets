# Agent quickstart

One path for an agent: install, run the commands below from the project directory, then restart the AI client. The site's agent console shows the same commands. No command here prints a secret value.

## Install

macOS:

```bash
brew tap ashlrai/phantom && brew trust --formula ashlrai/phantom/phantom && brew install ashlrai/phantom/phantom
```

Linux and Windows: follow the checksum-verified archive steps in the [README](../README.md#installation). Each package channel and the version it serves is in [distribution status](distribution-status.md).

## Commands

<!-- agent-quickstart:start -->
```bash
phantom init
phantom status --json
phantom list --json
phantom agent doctor --json
phantom setup --client claude
phantom setup --client cursor
phantom setup --client codex
phantom check
phantom why OPENAI_API_KEY --json
```
<!-- agent-quickstart:end -->

- `phantom init` moves secrets from `.env` into the vault and leaves `phm_` placeholders.
- `phantom setup --client` wires the MCP server into one AI client. Run only the line for your client; `windsurf` and `gemini` also work.
- `phantom status --json` reports project state. `phantom list --json` reports secret names only.
- `phantom agent doctor --json` is the value-free readiness check.
- `phantom check` reports secrets that are still unprotected.
- `phantom why OPENAI_API_KEY --json` explains one name. An `exec.delivery` of `no_route` means no built-in proxy route injects it.

## MCP files

`phantom setup` writes these for you, with the absolute path of the binary it found in `command`. They are shown so you can check the result.

Claude Code (project `.mcp.json`) and Cursor (`~/.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "phantom": {
      "command": "phantom",
      "args": ["mcp", "serve"]
    }
  }
}
```

Codex (`~/.codex/config.toml`):

```toml
[mcp_servers.phantom]
command = "phantom"
args = ["mcp", "serve"]
```

Restart the client, then ask it to call `phantom_status` and `phantom_list_secrets`. Do not ask it to reveal values.

Effectful MCP tools stay off unless the operator sets `PHANTOM_MCP_EFFECTS=trusted-terminal` outside the agent and approves each pending call with `phantom mcp-approve`.

## Read next

- [llms.txt](llms.txt) (compact) and [llms-full.txt](llms-full.txt) (full)
- [Claude Code](claude-code.md), [Cursor](cursor.md), [Codex](codex.md)
