# Phantom status for local orchestrators

Ashlr Hub and other local orchestrators can inspect whether a project has valid
Phantom configuration without opening its vault or managed dotenv file:

```bash
phantom status --json
```

This contract is implemented in the corrected source after `v0.7.8`. The
published `v0.7.8` binary accepted `--json` but returned human-readable status;
do not infer a configured project from that text. Consumers must reject missing
or unsupported schema versions and treat parse failures as unknown status.

## Schema version 1

An uninitialized project returns this JSON document with exit code zero:

```json
{
  "schema_version": 1,
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
| `proxy.lifecycle_lock` | `not-inspected` when configuration is unavailable; `missing` when no lock exists; `available` when the existing lock is not held; `held` when another process holds it; `unknown` when inspection fails |
| `proxy.listener_authenticated` | Always `false`: this command does not authenticate a listener |
| `issues` | Zero or more of `config-missing`, `config-unreadable`, `config-invalid`, `proxy-lock-unavailable` |

The observer does not create runtime storage, open the vault or dotenv, load
cloud credentials, read legacy proxy bearer state, or send network requests.
It reads configuration and inspects an existing machine-local lifecycle lock.
`--json` takes precedence over `--oneline`; operational failures such as inability
to resolve the working directory can still produce a nonzero exit code.

## Integrating with an orchestrator

Launch the installed binary with an argument array and the exact project working
directory. Bound execution time and output size. Require a successful exit,
valid JSON, `schema_version === 1`, and a boolean `initialized` field. Display
unknown status on any unsupported response; do not fall back to searching human
output for words such as "running" or "initialized".

Keep installation, project configuration, verified runtime connectivity, and
execution approval as separate states. In particular, neither `initialized`
nor a held lifecycle lock enables child environment injection or production
actions. Phantom's status report is an observation, not an authorization grant.

For a real CLI/MCP transport check without credentials, use the
[installed-runtime smoke example](../examples/agent-first-five-minutes/README.md).
For a scoped coding workflow, use the [delegation quickstart](delegation-quickstart.md).
