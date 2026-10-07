# Recipe: Phantom with Cursor

Protect a project's `.env` and add Phantom to Cursor's MCP servers without
disturbing the servers you already have.

## Steps in your own project

```text
phantom init
phantom setup --client cursor --print   # preview the snippet, write nothing
phantom setup --client cursor           # merge it into ~/.cursor/mcp.json
```

Restart Cursor. The `phantom` server appears in Settings → MCP, next to your
existing servers. Run your app with `phantom exec -- <command>` so it reaches
providers through the local proxy.

`~/.cursor/mcp.json` after setup, with an existing server preserved:

```json
{
  "mcpServers": {
    "other": { "command": "npx", "args": ["-y", "@example/other-mcp-server"] },
    "phantom": { "command": "/absolute/path/to/phantom", "args": ["mcp", "serve"] }
  }
}
```

Setup writes Cursor's user-level config, so the one `phantom` entry serves
every project. Each project is scoped by the `.phantom.toml` in the folder
Cursor opens.

## Run the recipe

[run.mjs](run.mjs) runs in a disposable workspace and HOME with a fake key. It
seeds `~/.cursor/mcp.json` with another server, runs setup, and then:

- checks that the other server is unchanged;
- launches the configured command over MCP stdio and calls `phantom_status`
  and `phantom_list_secrets`;
- asserts the value never appears in any response or any file in the
  workspace or HOME.

```text
node examples/cursor/run.mjs --phantom /absolute/path/to/phantom
```

```text
PASS phantom init protects the project's .env
PASS phantom setup --client cursor --print shows the snippet without writing anything
PASS phantom setup --client cursor adds Phantom to ~/.cursor/mcp.json and keeps existing servers
PASS the server Cursor launches answers phantom_status and names, not values, the secret
PASS neither the project nor Cursor's config holds the value
COMPLETE: Cursor recipe (5 checks)
```

This recipe passes against both the v0.7.9 release and the workspace build. It
does not drive Cursor's UI. See [docs/cursor.md](../../docs/cursor.md) for the
full guide.
