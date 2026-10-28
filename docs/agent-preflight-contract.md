# `phantom agent doctor --json` preflight contract

`phantom agent doctor --json` prints a value-free preflight that an agent
wrapper or orchestrator can check before it starts an agent in a repository.
It is a bounded readiness signal, not a certification that a repository or
agent is safe.

## Flags

| Flag | Effect |
|---|---|
| `--json` | Print the preflight below instead of the human view. The global `phantom --json` flag works too. |
| `--vault` | Also open the vault and check the cloud login. This reads the OS keychain. Without it the preflight reads only project files and environment variables: no vault open, no keychain access, no audit lines, no files written. |
| `--strict` | Shared exit table with `phantom doctor --strict` and `phantom why --strict`. Exit 0 when `verdict` is `ready`. Exit 2 when `verdict` is `degraded`, `blocked`, or `unknown`. Exit 1 is a command error and is not an issues-found result. |

Without `--strict` the exit code is always `0`; read the verdict from the
JSON. `--vault` and `--strict` require `--json`. Doctor `--strict` counts
every issue the same, including warnings. This preflight still records
severity on each check. Its exit code does not encode that severity: every
verdict other than `ready` is exit 2.

## Schema (version 1)

```json
{
  "schema": "phantom.agent.doctor.v1",
  "schema_version": 1,
  "kind": "phantom.agent.preflight",
  "verdict": "degraded",
  "readiness": "protected",
  "risk_level": "medium",
  "vault_probed": false,
  "checks": [
    { "id": "mcp-not-wired", "severity": "warning", "requires_approval": false },
    { "id": "vault-not-probed", "severity": "info", "requires_approval": false }
  ],
  "wrap": { "exec_ready": true, "blocked_by": [] }
}
```

| Field | Values |
|---|---|
| `schema` | `phantom.agent.doctor.v1`. This is the envelope id to key on. The `.vN` suffix changes only when the JSON shape breaks. It carries no project data. |
| `schema_version` | `1`. Kept so older readers keep working. |
| `kind` | `phantom.agent.preflight`. Kept so older readers keep working. |
| `verdict` | `ready` (no critical or warning checks), `degraded` (warnings only), `blocked` (any critical check), `unknown` (could not evaluate; `readiness` and `risk_level` are `null`) |
| `readiness` | `unsafe`, `protected`, `verified`, `team-ready`, `compliance-ready` |
| `risk_level` | `critical`, `high`, `medium`, `low`, `none` |
| `vault_probed` | `true` only with `--vault` |
| `checks[].id` | Fixed kebab-case ids. Service route findings collapse to `service-route-risk`. Without `--vault`, `vault-not-probed` (info) replaces any vault access check. |
| `checks[].severity` | `critical`, `warning`, `info` |
| `wrap.exec_ready` | `true` when no check is critical |
| `wrap.blocked_by` | The ids of the critical checks |

Checks are sorted by severity, then id, and deduplicated.

## Never appears

Secret names, secret values, placeholders, project ids, file paths, commands,
messages and error strings. Use `phantom agent report --json` or
`phantom agent doctor` for the full report with messages and fix commands.

## Stability rules

- Key on `schema` (`phantom.agent.doctor.v1`). `schema_version` and `kind` remain for older readers.
- The `.vN` suffix on `schema` changes only when the JSON shape breaks: a removed or renamed field, a changed type, or a changed enum value. New check ids and new fields stay on `v1`, and `schema_version` stays `1` beside that envelope id.
- Consumers should treat unknown check ids by their `severity`.
- The contract is pinned by `crates/phantom-cli/tests/agent_doctor_json_test.rs`.
