# Ashlr companion handshake v1

`phantom --ashlr-handshake` (with or without `--json`) prints one JSON
object and exits 0. This fast, local probe runs before command parsing and
logging. It opens no vault or keychain, makes no network requests, and reads
no project files. Secret names, values, mappings, resolved user paths and
environment contents never enter the response.

The response implements `ashlr-stack/contract/ashlr-handshake.v1.json` and
the rules in `lexicon/docs/ashlr-handshake.md`. The tests vendor the exact
contract and pin its SHA-256 so validation works offline.

`name` is `phantom-secrets`, `command` is `phantom`, and `version` is the
compiled package version. Protocol versions describe the bundled handshake,
MCP and agent preflight implementations. Capabilities describe bundled
features, not provider activation or hosted-service availability.

Health is `unknown` with no checks: discovery does not establish operational
or vault readiness. Use `phantom agent doctor --json` for agent readiness.
The static `edits` list describes common write locations, never resolved
user paths; receipts are empty. `doctor-fix` is deliberately omitted because
that shared capability requires a read-only plan, while Phantom's
`doctor --fix` writes repairs.

The probe accepts root boolean flags before `--ashlr-handshake`. A
subcommand, option value or `--` ends detection, so forwarded child arguments
and credential input cannot accidentally become a discovery request.
