# Agent-safe secret lookup

Use `phantom get OPENAI_API_KEY` (also accepts global `--json`) or the MCP
`phantom_get` tool with `{"name":"OPENAI_API_KEY"}`. Both return the same JSON
metadata contract, without opening the vault, retrieving credentials, making
network requests, or returning persistent mappings. No approval token is needed.

The version 1 fields are:

| Field | Meaning |
| --- | --- |
| `name` | Exact environment variable name requested |
| `initialized` | Project configuration is present and valid |
| `exists` | Exact name occurs in the managed dotenv |
| `existence_source` | Always `managed_dotenv` |
| `vault_inspected` | Always `false` |
| `route` | Built-in upstream for proxied delivery, otherwise `null` |
| `delivery_mode` | `exec_delivery_for_key` label; `null` before initialization |
| `expires_at` | Configured Unix timestamp in seconds, or `null` |
| `schema_version` | `1` |

`exists` does not establish that a vault value exists or is accessible. A vault
entry absent from the managed dotenv is not reported as present. Delivery mode
classifies the key alone; it does not authorize execution or establish that
configuration-wide checks, expiry checks, or vault preflight will pass. A null
expiry means no expiry metadata is configured, not an assurance of validity.

Before initialization, lookup observes the regular project-local `.env`. After
initialization it respects the configured managed dotenv. Symlinks, malformed
files and invalid configuration fail closed. Errors omit parser contents.

Plaintext remains available only through `phantom reveal NAME` in a trusted
human terminal, with its typed confirmation. Printing also requires stdout to
be a terminal; piping reveal into another command is refused. Agents must never
emulate the terminal ceremony. `get` has no reveal or plaintext flag.
