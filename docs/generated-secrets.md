# Generate a secret without exposing its value

After `phantom init --empty`, run:

```sh
phantom add SESSION_SECRET --generate
```

Phantom generates 32 bytes with the operating system random source, encodes
those bytes as 64 lowercase hexadecimal characters, and stores that value in
the vault. Standard output is a JSON object with exactly `name` and
`fingerprint`. The fingerprint is `sha256:` followed by the full SHA-256 digest
of the stored UTF-8 value. The generated value and persistent dotenv mapping
are never printed. Secret buffers are zeroized when dropped.

Generation creates a new name only. Existing vault entries, dotenv assignments,
and lifecycle ownership are refused. Config, vault, and managed dotenv changes
share an exact-before transaction; concurrent drift aborts the transaction.
Generation requires an initialized project and a complete, unlocked inventory.
`--generate` cannot be combined with a positional value, `--stdin`,
`--multiline`, or `--first-line`. It reads no secret input.

MCP callers use `phantom_add_secret` with `name`, `generate: true`,
`confirm: true`, and the existing one-use out-of-band `approval_token`.
The default-denied effects gate still applies: the operator must enable
`PHANTOM_MCP_EFFECTS=trusted-terminal` outside agent authority and approve the
exact request in a trusted terminal. Approval for a request without generation
does not authorize generation. MCP returns the same value-free JSON receipt.
No tool accepts a plaintext value; `generate` defaults to false for compatibility.

These are local application secrets, suitable for purposes such as session
signing. They do not create credentials at an external provider. Use
`phantom_add_secret_interactive` to store a provider-issued credential outside
agent context. Run supported consumers through `phantom exec -- <command>`;
generation does not add a new proxy route or expose a raw-value delivery path.
