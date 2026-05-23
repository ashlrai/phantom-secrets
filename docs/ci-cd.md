# CI/CD Integration

Phantom's current CI support is strongest when secrets are synced into a deployment platform before the build runs. Direct Phantom Cloud pull from headless CI is not supported yet because the CLI does not currently expose a non-interactive cloud login flow.

## GitHub Actions

Use GitHub Actions for checks, builds, and deploy commands, but do not rely on the disabled Phantom GitHub Action for cloud vault pulls.

```yaml
name: Build
on: push

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Check for unprotected secrets
        run: npx phantom-secrets check --staged

      - name: Build
        run: npm ci && npm run build
```

The repository action at `integrations/github-actions/action.yml` is a fail-fast placeholder until a supported non-interactive Phantom Cloud auth flow exists.

## Vercel

```bash
# One-time or release-time: sync secrets to Vercel
phantom sync --platform vercel --project prj_xxxxx

# Or add to .phantom.toml:
# [[sync]]
# platform = "vercel"
# token_env = "VERCEL_TOKEN"
# project_id = "prj_xxxxx"
```

After configuring, `phantom sync` pushes vault secrets to Vercel environment variables. Your GitHub Actions workflow can then trigger a Vercel deploy using Vercel's standard GitHub integration or CLI.

## Railway

```bash
# Sync secrets to Railway
phantom sync --platform railway --project your-project-id
```

Railway is the other supported sync platform. Store the Railway token in the environment where you run `phantom sync`; Phantom reads the platform token at sync time and does not store it in `.phantom.toml`.

## EAS Build (Expo)

EAS does not support arbitrary local proxy injection during hosted builds. Sync or enter secrets into EAS using Expo's own secret-management flow, then keep `phantom check` in CI to prevent raw `.env` secrets from being committed.

## Docker

For Docker builds, use build-time secret mounting:

```dockerfile
# syntax=docker/dockerfile:1
RUN --mount=type=secret,id=env,target=/app/.env npm run build
```

```bash
# Build with secrets from a local Phantom-protected checkout
phantom exec -- docker build --secret id=env,src=.env .
```

## General Pattern

For CI/CD today:

1. Protect local secrets with `phantom init`.
2. Sync deploy-time secrets to a supported platform with `phantom sync --platform vercel` or `phantom sync --platform railway`.
3. Run CI checks such as `phantom check --staged`.
4. Let the deployment platform inject secrets into builds and runtime.

Do not use undocumented CI token environment variables for Phantom Cloud pulls. Direct cloud pull in CI will be documented here once the CLI supports it.
