# Consuming metadata-only Phantom status

Use `phantom status --json` to observe a project's local configuration without
opening its vault or managed dotenv. Run the installed executable with an
argument array (`["status", "--json"]`) and the intended project as its working
directory. Apply a timeout and an output-size limit; capture the exit status
and parse one complete JSON document. Do not interpret human-readable status
or `--oneline` output as this contract.

This is the CLI `phantom.status` contract, not the MCP `phantom_status` tool:
the latter reports project and service metadata and dotenv counts. Treat that
metadata as sensitive and do not substitute it for the fixed-vocabulary CLI
response in logs or consumers. See [the status contract](hub-status-contract.md)
for the complete CLI schema and [MCP documentation](mcp-secrets-manager.md) for
the separate tool.

## Redacted example fixtures

These synthetic documents contain no project identifiers, paths, secret names,
values, or placeholder mappings. They match the existing CLI test fixtures; they
are examples of observations, not evidence about any actual project.

Missing configuration:

```json
{
  "schema_version": 1,
  "kind": "phantom.status",
  "initialized": false,
  "inspection": "metadata-only",
  "managed_dotenv": { "inspected": false },
  "vault": { "inspected": false },
  "proxy": { "lifecycle_lock": "not-inspected", "listener_authenticated": false },
  "issues": ["config-missing"]
}
```

Valid configuration, with no lifecycle lock record:

```json
{
  "schema_version": 1,
  "kind": "phantom.status",
  "initialized": true,
  "inspection": "metadata-only",
  "managed_dotenv": { "inspected": false },
  "vault": { "inspected": false },
  "proxy": { "lifecycle_lock": "missing", "listener_authenticated": false },
  "issues": []
}
```

Invalid configuration has `initialized: false`, `lifecycle_lock:
"not-inspected"`, and `issues: ["config-invalid"]`. An unreadable or symlinked
configuration similarly reports `config-unreadable`. If lock inspection fails
with valid configuration, the lock is `unknown` and the issue is
`proxy-lock-unavailable`. The tests in
[`status_json_test.rs`](../crates/phantom-cli/tests/status_json_test.rs) pin
these cases and check that canary metadata does not leak.

## Consumer decisions

1. On timeout, output limit, nonzero exit, malformed JSON, or a missing or
   unsupported `kind` or `schema_version`, report **unknown**. Require
   `kind` to equal `phantom.status`, `schema_version` to equal `1`, and
   `initialized` to be a boolean. Do not guess from text or another JSON kind.
2. For a recognized response, `initialized: true` means only that a regular
   project configuration file was read and parsed. `false` does not imply an
   empty vault. Surface known issue codes as observations; treat unfamiliar enum
   values as unknown and ignore extra fields for forward compatibility.
3. Keep configuration, vault availability, credential validity, authenticated
   proxy connectivity, and authorization as separate states. A `held` lock
   does not authenticate or identify a listener. Neither it nor initialization
   grants permission to run an action. The response explicitly says the vault
   and managed dotenv were not inspected.

The `kind` discriminator was added after the immutable v0.7.9 release. Earlier
binaries can emit version 1 without it; a consumer following these rules must
report those responses as unknown rather than assuming their identity. See the
[contract's stability rules](hub-status-contract.md#stability-rules) before
building a parser.
