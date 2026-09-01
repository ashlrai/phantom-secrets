# Phantom Secrets — Railway Integration

Manually sync selected vault values to Railway service variables through the
Railway GraphQL API. This transmits the selected plaintext values to Railway;
it is separate from Phantom Cloud's client-encrypted personal-vault backup.

## Status

Under development. Currently, `phantom sync --platform railway` uses the
Railway GraphQL API with a user-supplied token. Preview with `--dry-run --json`
before running the separately reviewed live sync. The marketplace integration
and automatic token management are not shipped.

## Architecture

Current source workflow:

1. The user supplies Railway credentials and selects an exact project,
   service, and environment.
2. `phantom sync --platform railway` sends selected values directly to the
   Railway API after the command's reviewed sync flow.
3. `phantom cloud push` uploads only a client-encrypted personal-vault backup;
   it never deploys or auto-syncs Railway variables.
