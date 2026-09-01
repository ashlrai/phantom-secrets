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

      - name: Install the immutable Phantom v0.7.3 Linux release
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          gh release download v0.7.3 --repo ashlrai/phantom-secrets \
            --pattern phantom-x86_64-unknown-linux-gnu.tar.gz \
            --pattern phantom-x86_64-unknown-linux-gnu.tar.gz.sha256
          sha256sum -c phantom-x86_64-unknown-linux-gnu.tar.gz.sha256
          tar -xzf phantom-x86_64-unknown-linux-gnu.tar.gz
          install -d "$HOME/.local/bin"
          install -m 0755 phantom phantom-mcp "$HOME/.local/bin/"
          echo "$HOME/.local/bin" >> "$GITHUB_PATH"

      - name: Check for unprotected secrets
        run: phantom check

      - name: Build
        run: npm ci && npm run build
```

The repository action at `integrations/github-actions/action.yml` is a fail-fast placeholder until a supported non-interactive Phantom Cloud auth flow exists.
The example downloads an immutable reviewed release and verifies its published
checksum before executing it; do not replace it with an unpinned registry
command. Select the matching asset for ARM64 or a non-Linux runner.

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

### Observe the hosted deployment

The staged web application exposes two no-store, provider-free operational
routes:

- `GET /api/v1/health` returns process liveness and an all-or-nothing build
  identity. It returns `200` even when deployment identity is unavailable so a
  monitor can distinguish a running process from an identified build.
- `GET /api/v1/ready` returns `200` only when immutable Vercel build identity,
  core auth configuration, and every explicitly commissioned hosted service
  are structurally configured. Otherwise it returns `503`.

Readiness is deliberately `configuration_only`. Its response records provider
acceptance as `not_checked` and customer acceptance as `not_established`; it
does not call Supabase, Stripe, Vercel, or a customer workflow. Responses expose
only deterministic states and validated build metadata, never credential or
environment-variable values.

Vercel must supply `VERCEL_GIT_COMMIT_SHA`, `VERCEL_DEPLOYMENT_ID`, and
`VERCEL_ENV`. Core configuration also requires the three Supabase variables in
`apps/web/.env.local.example`. Exact `true` feature gates add their documented
service-specific configuration requirements. A successful source build does
not prove those variables exist in the deployed environment.

After an authorized deployment, record both endpoint responses together with
the immutable deployment identifier and source SHA. Then verify provider and
authenticated user flows separately. Do not promote a `200` readiness response
into a provider-activation or customer-acceptance claim.

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
3. Run CI checks such as `phantom check`.
4. Let the deployment platform inject secrets into builds and runtime.

Do not use undocumented CI token environment variables for Phantom Cloud pulls. Direct cloud pull in CI will be documented here once the CLI supports it.
