### Added (versioned `--json` output for `env`, `audit path`, and `add`)

- `phantom env --json`, `phantom audit path --json`, and
  `phantom add NAME --generate --json` print one JSON object on stdout with a
  `schema` field (`env.v1`, `audit.path.v1`, `add.v1`). They report names and
  metadata only, never secret values or persistent mappings.
- With `--json`, a command failure prints
  `{"schema":"error.v1","code":"command_failed","message":"..."}` on stderr and
  exits nonzero. Output without `--json` is unchanged. The README gains a
  "Machine output" section describing the contract.
