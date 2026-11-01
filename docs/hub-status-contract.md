# Phantom status for local orchestrators

Ashlr Hub and other local orchestrators can inspect whether a project has valid
Phantom configuration without opening its vault or managed dotenv file:

```bash
phantom status --json
```

This contract ships in the `v0.7.9` release. The earlier `v0.7.8` binary
(still installed by the Homebrew formula until it is bumped) accepted `--json`
but returned human-readable status;
do not infer a configured project from that text. Consumers must reject missing
or unsupported schema versions and treat parse failures as unknown status.

## Schema version 1

An uninitialized project returns this JSON document with exit code zero:

```json
{
  "schemaVersion": 1,
  "schema_version": 1,
  "kind": "phantom.status",
  "initialized": false,
  "inspection": "metadata-only",
  "managed_dotenv": { "inspected": false },
  "vault": { "inspected": false },
  "proxy": {
    "lifecycle_lock": "not-inspected",
    "listener_authenticated": false
  },
  "issues": ["config-missing"]
}
```

`initialized: true` means only that the project's `.phantom.toml` was readable
as a regular file and parsed successfully. It does not establish vault access,
credential validity, proxy connectivity, client activation, or authority to act.
Config contents, project IDs, paths, secret names, and values are not returned.
Parse errors become fixed issue codes rather than arbitrary parser diagnostics.

| Field | Values and meaning |
|---|---|
| `kind` | Always `phantom.status`: the schema id that distinguishes this document from other Phantom JSON contracts (such as `phantom.agent.preflight`), which share `schema_version: 1` |
| `proxy.lifecycle_lock` | `not-inspected` when configuration is unavailable; `missing` when no lock exists; `available` when the existing lock is not held; `held` when another process holds it; `unknown` when inspection fails |
| `proxy.listener_authenticated` | Always `false`: this command does not authenticate a listener |
| `issues` | Zero or more of `config-missing`, `config-unreadable`, `config-invalid`, `proxy-lock-unavailable` |

`kind` was added to the contract after the immutable `v0.7.9` shipment; builds
predating it emit the same `schema_version: 1` document without `kind`. Under
the consumer requirements below, such a build reports as unknown status.

The observer does not create runtime storage, open the vault or dotenv, load
cloud credentials, read legacy proxy bearer state, or send network requests.
It reads configuration and inspects an existing machine-local lifecycle lock.
`--json` takes precedence over `--oneline`; operational failures such as inability
to resolve the working directory can still produce a nonzero exit code.

## Stability rules

- Within `schema_version: 1` changes are additive only: new optional fields and
  new enum values may appear. Consumers must ignore unknown fields and treat an
  unknown enum value as `unknown`.
- Removing or renaming a field, or changing a field's type, bumps
  `schema_version`.
- When JSON is printed the exit code is zero; problems are reported in `issues`.

These values never appear in the output: secret values, `phm_` placeholder
tokens, secret names, dotenv contents, configuration values (service names,
patterns, project IDs), filesystem paths, error strings, PIDs, and hostnames.
The output contains only the fixed vocabulary above, booleans, and small
integers.

The exact document for each configuration state (initialized, missing,
invalid, symlinked to another project) and the canary-leak checks are pinned in
`crates/phantom-cli/tests/status_json_test.rs`.

## Integrating with an orchestrator

Launch the installed binary with an argument array and the exact project working
directory. Bound execution time and output size. Require a successful exit,
valid JSON, `kind === "phantom.status"`, `schema_version === 1`, and a boolean
`initialized` field. Display
unknown status on any unsupported response; do not fall back to searching human
output for words such as "running" or "initialized".

Keep installation, project configuration, verified runtime connectivity, and
execution approval as separate states. In particular, neither `initialized`
nor a held lifecycle lock enables child environment injection or production
actions. Phantom's status report is an observation, not an authorization grant.

For a real CLI/MCP transport check without credentials, use the
[installed-runtime smoke example](../examples/agent-first-five-minutes/README.md).
For a scoped coding workflow, use the [delegation quickstart](delegation-quickstart.md).

`schemaVersion: 1` is the camelCase version field shared with `phantom doctor --json`.
Status retains `schema_version: 1` for existing consumers; both identify the same
version. Doctor retains `schema: "phantom.doctor.v1"` and its diagnostic checks,
fix hints, and client names/states. Neither output includes credential values or
managed placeholder mappings. Status intentionally also omits secret names.
