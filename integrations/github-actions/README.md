# Phantom Secrets -- GitHub Actions

The GitHub Action is intentionally disabled in this release.

Earlier drafts documented a CI device-token flow (`phantom login --ci`) and action inputs that the current CLI does not support. Keeping those instructions published would cause broken CI setups, so the action now fails fast with a clear message.

## Current CI Options

- Use `phantom sync --platform vercel --project <id>` or `phantom sync --platform railway --project <id>` before deployment.
- Use the platform's own secret store during CI/CD after syncing from Phantom.
- Run `phantom check --staged` in CI to prevent unprotected `.env` secrets from landing in the repository.

## Not Supported Yet

- Non-interactive Phantom Cloud login in GitHub Actions.
- `phantom cloud pull --env`.
- `phantom list --count`.
- A CI-safe GitHub Action that pulls Phantom Cloud vaults directly.

See `docs/ci-cd.md` for supported patterns.
