# Launch a protected MCP server

From an initialized project, `phantom mcp run` starts a named local stdio
server using the same vault, lifecycle checks, authenticated proxy, and
signal forwarding as `phantom exec`:

```sh
phantom mcp run search
phantom mcp run search --config servers.json
```

The default config is `.mcp.json` in the current directory. For example:

```json
{
  "mcpServers": {
    "search": {
      "command": "node",
      "args": ["./servers/search.mjs"],
      "env": { "LOG_LEVEL": "warn" },
      "type": "stdio"
    }
  }
}
```

This workflow protects the managed keys loaded for the active project environment;
it does not open or scan unrelated vault entries or other environments.

Protect API keys with `phantom init` or `phantom add NAME` in a trusted terminal
before launching. Omit protected keys from the server's `env`: Phantom supplies
fresh `phm_` session placeholders for the managed dotenv's protected names.
An existing `phm_` entry under a protected name is accepted as a marker and
discarded; it never selects a vault entry or resolves to plaintext. No variable
or shell expansion is performed. `command` is one executable, and `args` are
passed individually. Pin and install the server locally before configuring it.

The child receives SDK base URLs for built-in routes with loaded credentials.
Only the parent proxy reads the vault values and injects them into a matched
route's fixed auth header. The server must honor its SDK's base URL override.
An unsupported key receives only an inert placeholder and a warning; use
`phantom why NAME` to inspect route support. Connection strings, expired or
missing values, locked vaults, and modified upstream routes retain exec's
fail-closed behavior.

Configured env cannot override Phantom's internal variables or proxy URL
variables. Literal protected env values and literal mappings in argv are
refused. Arguments or configured env containing a loaded vault value are
refused without echoing them; inherited aliases containing those values are
removed. Inherited `PHANTOM_*` variables and stale mapping values are removed
before fresh session metadata is supplied. Next.js public-variable detection
is disabled for this launch path.

The launcher preserves stdin, stdout, stderr, child exit status, and exec's
termination handling. Its own progress output is suppressed so stdout remains
the server's MCP stream. The proxy shuts down when the child exits. These are
process-launch protections for managed credentials, not a sandbox for an
untrusted server or protection against a server reading other accessible files.

Only local stdio transport is supported. Selected-server fields are `command`,
`args`, `env`, and optional `type: "stdio"`; unsupported fields fail closed.
The config must be a regular file, not a final symlink, and at most 1 MiB.
Relative executable and argument paths use the current project directory,
including when `--config` points elsewhere. Configs may include other servers
and top-level client metadata; only the named server is launched.

`phantom mcp serve` still runs Phantom's own secret-management MCP server.
Launching an external server does not grant Phantom MCP effect approval and
does not change client configuration or the MCP tool catalog.
