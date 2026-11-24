# Generate a secret without exposing its value

After `phantom init --empty`, run:

```sh
phantom add SESSION_SECRET --generate
```

Phantom generates 32 bytes with the operating system random source, encodes
those bytes as 64 lowercase hexadecimal characters, and stores that value in
the vault. Standard output is a JSON object with exactly `name` and
`fingerprint`. `--json` adds `schema` (`add.v1`), `durability_verified`, and
`warnings`, and does not repeat the durability warning on stderr. The
fingerprint is `sha256:` followed by the full SHA-256 digest of the stored
UTF-8 value. The generated value and persistent dotenv mapping are never
printed. Secret buffers are zeroized when dropped.

Generation creates a new name only. Existing vault entries, dotenv assignments,
and lifecycle ownership are refused. Config, vault, and managed dotenv changes
share an exact-before transaction; concurrent drift aborts the transaction.
Generation requires an initialized project and a complete, unlocked inventory.
`--generate` cannot be combined with a positional value, `--stdin`,
`--multiline`, `--first-line`, or `--dry-run`. It reads no secret input.

MCP callers use `phantom_add_secret` with `name`, `generate: true`,
`confirm: true`, and the existing one-use out-of-band `approval_token`.
The default-denied effects gate still applies: the operator must enable
`PHANTOM_MCP_EFFECTS=trusted-terminal` outside agent authority and approve the
exact request in a trusted terminal. Approval for a request without generation
does not authorize generation. MCP returns the same value-free `name` and
`fingerprint` receipt. The CLI `--json` form is the one that adds durability.
No tool accepts a plaintext value; `generate` defaults to false for compatibility.

Generation stores random material locally; it does not create credentials at
an external provider or add a proxy route. Use
`phantom_add_secret_interactive` to store a provider-issued credential outside
agent context.

For the `SESSION_SECRET` example, inspect delivery without reading the value:

```sh
phantom why SESSION_SECRET --json
```

`exec.delivery: no_route` means the child receives only a fresh placeholder.
A session-signing library that reads `SESSION_SECRET` directly would sign with
that placeholder, not the stored random value; a later exec session receives
a different placeholder. Generation alone therefore does not establish a
working session-signing setup. There is no general raw-value delivery path in
`phantom exec`. Consumers need a supported proxy route or a separately reviewed
trusted workflow outside the value-blind agent boundary. See
[exec coverage](exec.md).
