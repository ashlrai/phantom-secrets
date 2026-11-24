# Phantom Secrets — Railway Integration

Manually sync selected vault values to Railway service variables through the
Railway GraphQL API. This transmits the selected plaintext values to Railway;
it is separate from Phantom Cloud's client-encrypted personal-vault backup.

## Status

Under development. Currently, `phantom sync --platform railway` uses the
Railway GraphQL API with a user-supplied token. Preview with `--dry-run --json`
before running the separately reviewed live sync. The marketplace integration
and automatic token management are not shipped.

## Current CLI Flow

```bash
export RAILWAY_TOKEN=...
phantom sync --platform railway --project your-project-id --dry-run --json
phantom sync --platform railway --project your-project-id
```

Without configuration, the sync targets the `production` environment at the
project level. To pick a service or another environment, add a `[[sync]]`
block with `service_id` and `environment_id` to `.phantom.toml`; see
[docs/sync.md](../../docs/sync.md#railway).

The live sync needs attached terminals: it prints the plan and asks you to type
an exact `SYNC <plan-digest> <nonce>` challenge before it reads any vault
value, so it cannot run headlessly in CI. In the other direction,
`phantom pull --from railway --project <id>` (with optional `--service` and
`--environment`) fetches Railway variables into the local vault and managed
`.env` entries, behind its own `PULL` terminal challenge.

## Architecture

Current source workflow:

1. The user supplies Railway credentials and selects an exact project,
   service, and environment.
2. `phantom sync --platform railway` sends selected values directly to the
   Railway API after the command's reviewed sync flow.
3. `phantom cloud push` uploads only a client-encrypted personal-vault backup;
   it never deploys or auto-syncs Railway variables.
