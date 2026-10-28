### Added (`phantom add --generate`)

- `phantom add <KEY> --generate` stores a locally generated 256-bit random
  secret and prints only a value-free JSON receipt (`name` plus its SHA-256
  `fingerprint`). Creation is create-only inside the same exact-before
  transaction as `add`, so existing names are always refused.
- MCP `phantom_add_secret` accepts `generate: true` behind the existing
  `confirm` plus one-use `approval_token` gates; with `generate` unset it
  keeps refusing plaintext. See `docs/generated-secrets.md`.
