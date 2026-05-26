# Phantom Secrets — Vercel Integration

The production Vercel integration is still under development. Today,
deployment sync is performed by the CLI with a local `VERCEL_TOKEN`; Phantom
Cloud does not yet auto-sync vaults into Vercel from connected OAuth tokens.

## Current CLI Flow

```bash
export VERCEL_TOKEN=...
phantom sync --platform vercel --project prj_your_project_id --dry-run --json
phantom sync --platform vercel --project prj_your_project_id
```

`--dry-run --json` previews the target, selected secret names, filters, and
missing token state without decrypting vault values or calling the Vercel API.

## Planned Integration

The intended hosted integration will:

1. Require a signed Phantom user session before install.
2. Validate OAuth state in the callback.
3. Store Vercel OAuth tokens encrypted at rest.
4. Show safe connection metadata in the dashboard.
5. Let the CLI or cloud backend use connected integration credentials without
   exposing tokens to an AI agent.

Until that lands, use the CLI token flow above.
