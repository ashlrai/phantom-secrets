### Added (`secret://NAME` references in `phantom exec`)

- A launcher can pass `NAME=secret://NAME` to `phantom exec`. The name is
  protected like a dotenv phantom token: the child gets a session token, the
  proxy holds the value, and an `exec.secret_ref` audit event names the secret.
  Malformed, mismatched or reserved references stop the launch with a
  value-free message. Design: `docs/design/builtin-vault.md`.
