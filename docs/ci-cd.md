# CI/CD Integration

Phantom keeps secrets in an encrypted vault locally. For CI/CD pipelines, use Phantom Cloud to pull secrets at build time.

## GitHub Actions

```yaml
name: Build
on: push

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Pull secrets from Phantom Cloud
        env:
          PHANTOM_CLOUD_TOKEN: ${{ secrets.PHANTOM_CLOUD_TOKEN }}
        run: npx phantom-secrets cloud pull

      - name: Build
        run: npx phantom-secrets exec -- npm run build
```

**Setup:**
1. Run `phantom login` locally
2. Run `phantom cloud push` to upload your vault
3. Add `PHANTOM_CLOUD_TOKEN` to your GitHub repo secrets (Settings > Secrets)
4. Get your token: `phantom reveal PHANTOM_CLOUD_TOKEN --yes` (or copy from `phantom login` output)

## Vercel

```bash
# One-time: sync secrets to Vercel
phantom sync --platform vercel --project prj_xxxxx

# Or add to .phantom.toml:
# [[sync]]
# platform = "vercel"
# project_id = "prj_xxxxx"
```

After configuring, `phantom sync` pushes all secrets to Vercel environment variables.

## EAS Build (Expo)

EAS doesn't support custom CLIs during build. Export secrets for EAS:

```bash
# Export secrets in EAS format
phantom export --format env | eas secret:push --force
```

Or set secrets manually in eas.json:
```json
{
  "build": {
    "production": {
      "env": {
        "SUPABASE_SERVICE_ROLE_KEY": "@phantom-supabase-key"
      }
    }
  }
}
```

## Fly.io

```bash
# Sync secrets to Fly.io
phantom sync --platform fly
```

## Railway

```bash
# Sync secrets to Railway
phantom sync --platform railway --project your-project-id
```

## Docker

For Docker builds, use build-time secret mounting:

```dockerfile
# syntax=docker/dockerfile:1
RUN --mount=type=secret,id=env,target=/app/.env npm run build
```

```bash
# Build with secrets
phantom exec -- docker build --secret id=env,src=.env .
```

## General Pattern

For any CI/CD system:

1. **Store vault in cloud:** `phantom cloud push`
2. **Pull in CI:** `PHANTOM_CLOUD_TOKEN=xxx npx phantom-secrets cloud pull`
3. **Run with proxy:** `npx phantom-secrets exec -- <build-command>`

The proxy runs locally in CI just like on your dev machine. Secrets never appear in environment variables or build logs.
