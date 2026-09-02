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

- `GET /api/v1/health` returns coarse route/runtime liveness. It returns `200`
  even when deployment identity is unavailable so a monitor can distinguish an
  executing route from dependency or configuration readiness.
- `GET /api/v1/ready` returns `200` only when complete Vercel deployment identity,
  core auth configuration, and all applicable local configuration checks pass.
  Commissioned billing additionally requires structurally valid Stripe
  configuration; the personal-vault and team gates add no provider check.
  Otherwise it returns `503`.

Readiness is deliberately `configuration_only`. It does not call Supabase,
Stripe, Vercel, or a customer workflow, and therefore never establishes
provider or customer acceptance. Public responses expose only status, service,
and release version. Source revision, deployment ID/environment, validation
reasons, service commissioning state, credentials, and environment-variable
values remain outside the anonymous response contract.

Enable access to Vercel's
[system environment variables](https://vercel.com/docs/environment-variables/system-environment-variables)
in project settings so `VERCEL_GIT_COMMIT_SHA`, `VERCEL_DEPLOYMENT_ID`, and `VERCEL_ENV`
exist. This is external deployment configuration; source cannot enable or prove
it. Core configuration also requires the three Supabase variables in
`apps/web/.env.local.example`: both `NEXT_PUBLIC_*` variables must be valid at
build time and remain byte-for-byte consistent and valid at runtime; a
non-secret SHA-256 fingerprint binds the two phases. `SUPABASE_SERVICE_ROLE_KEY`
is validated only at runtime. Runtime injection cannot repair a browser bundle
built without or for a different public configuration. Exact `true` feature gates add only
their documented local requirements. A successful source build does not prove
runtime variables exist in the deployed environment.

After an authorized deployment, record both coarse endpoint responses and
collect the deployment identifier and source SHA from authenticated Vercel
deployment metadata. Then verify provider and
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
