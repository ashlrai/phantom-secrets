# Phantom Secrets — Railway Integration

Auto-sync encrypted secrets from your Phantom vault to Railway service variables.

## Status

Under development. Currently, `phantom sync --platform railway` uses the Railway GraphQL API with a manual token. The marketplace integration will automate token management.

## Architecture

Same pattern as the Vercel integration:
1. OAuth flow gives Phantom a Railway API token
2. `phantom cloud push` auto-syncs to Railway
3. Supports per-service and per-environment variables
