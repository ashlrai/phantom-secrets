# Phantom Secrets — Vercel Integration

Auto-sync encrypted secrets from your Phantom vault to Vercel environment variables.

## How It Works

1. Install the Phantom integration from the [Vercel Marketplace](https://vercel.com/integrations)
2. Link your Phantom Cloud account (GitHub OAuth)
3. Select which Vercel projects to sync
4. `phantom cloud push` now auto-syncs to Vercel — no manual token setup

## Architecture

```
phantom vault (local)
    ↓ phantom cloud push
Phantom Cloud (E2E encrypted)
    ↓ auto-sync (if Vercel integration installed)
Vercel Environment Variables
```

- Phantom decrypts secrets server-side only to push to Vercel API
- Uses Vercel's OAuth token (stored encrypted in Supabase)
- Syncs production, preview, and development environments

## Setup

1. Go to [phm.dev/integrations/vercel/install](https://phm.dev/integrations/vercel/install)
2. Authorize Phantom to access your Vercel account
3. Select projects to sync
4. Done — `phantom cloud push` now syncs everywhere

## CLI Usage

```bash
# Sync to Vercel (uses integration token automatically)
phantom sync --platform vercel

# Sync to all configured platforms
phantom sync --all

# Push to cloud + auto-sync to all integrations
phantom cloud push --sync
```

## Status

This integration is under development. Currently, `phantom sync --platform vercel` requires a manual `VERCEL_TOKEN` environment variable. The marketplace integration will remove this requirement.
