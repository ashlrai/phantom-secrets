# Local generated rotation

`phantom rotate NAME --generate` replaces an existing local secret with 32 bytes
of OS randomness, encoded as 64 hexadecimal characters. It preserves the managed
dotenv and its persistent placeholder. This is intended for application-owned
random secrets. It does not issue or revoke provider API keys: replacing a vendor
credential locally will not make that vendor accept the generated value.

The command requires attached trusted terminals and exact typed consent. MCP
clients use `phantom_rotate` with `name`, `generate: true`, `confirm: true`, and a
parameter-bound, one-use `approval_token`. The operator-controlled effects gate
still applies. Agents must never emulate the terminal approval ceremony.

Both paths return only `name`, `route` (configured service name or null),
`rotated_at` (Unix seconds), and `version`. They never return a value or mapping.
The first generated successor is version 2. Fresh exec sessions read the new
value. Processes already running retain their previously injected values.

The encrypted file vault commits the new value, version, timestamp and one
predecessor in one locked encrypted-file replacement. Validation verdicts are
cleared. Existing lifecycle metadata and deadlines remain unchanged; expired
or read-only entries are refused. Backends without atomic local versioning,
including the OS keychain, fail closed; there is no automatic backend migration.

For rollback, an operator outside agent authority runs:

```sh
phantom rotate --name NAME --rollback
```

Rollback requires attached terminals and a fresh exact challenge, restores the
single predecessor, consumes that predecessor, increments the version, and does
not renew lifecycle age. It is not exposed through MCP. Another generation
replaces the retained predecessor. Ordinary store/CAS replacement and deletion
remove local history; recreating a name cannot resurrect deleted history.
History is local and is not included in cloud/team export or migration.

The persisted active environment selects the same namespaced entry as exec;
only the default environment permits a legacy bare-name fallback. Each entry's
history is isolated by project and environment. Provider rotation compatibility
endpoints retain their existing hard denials.
