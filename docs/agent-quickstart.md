# Agent quickstart

Paste these commands. They do not print secret values. Replace nothing in the blocks below.

Install both verified `v0.7.9` binaries before setup. Version `0.7.9` has no network package-runner fallback and fails closed when neither local runtime is executable. Package channels are recorded in [distribution status](distribution-status.md).

## Install

macOS, one paste:

```bash
brew tap ashlrai/phantom && brew trust --formula ashlrai/phantom/phantom && brew install ashlrai/phantom/phantom
```

Linux and Windows: follow the checksum-checked archive steps in the repository [README](../README.md#installation).

## Commands

From the project directory:

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

`phantom status --json` reports project state. `phantom list --json` reports secret names. `phantom why OPENAI_API_KEY --json` explains one name. `exec.delivery` of `no_route` means no built-in proxy route injects that name.

## MCP files

`phantom setup` writes the absolute path of the binary it found. The files below are the same shape with `phantom` on `PATH`.

Claude Code, project `.mcp.json`:

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

Cursor, `~/.cursor/mcp.json`, uses that same JSON.

Codex, `~/.codex/config.toml`:

```toml
[mcp_servers.phantom]
command = "phantom"
args = ["mcp", "serve"]
```

Restart the client. Ask it to call `phantom_status` and `phantom_list_secrets`. Do not ask it to reveal values.

Effectful MCP tools stay disabled unless the operator sets `PHANTOM_MCP_EFFECTS=trusted-terminal` outside the agent and completes `phantom mcp-approve`.

## Read next

- [llms.txt](llms.txt)
- [llms-full.txt](llms-full.txt)
- [Claude Code](claude-code.md)
- [Cursor](cursor.md)
- [Codex](codex.md)
