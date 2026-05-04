# phantom sync — Deploy Platform Secret Sync

`phantom sync` pushes secrets from your local vault to deployment platforms (Vercel and Railway). It reads real values from the OS keychain, applies any filters you configure, and calls the platform API directly — no secrets are written to disk or logged.

Before using sync, complete the basic setup: [getting-started.md](./getting-started.md).

---

## How it works

1. Phantom reads secret names from the vault and decrypts their values.
2. For each configured sync target, it compares the local values against what the platform currently has.
3. Keys that are new or changed are upserted. Keys that match exactly are skipped.
4. Secrets are zeroized from memory after all targets have been processed.

The platform token (e.g., `VERCEL_TOKEN`) is read from your local environment — it is never stored in `.phantom.toml`.

---

## Vercel

### One-time run without configuration

```bash
export VERCEL_TOKEN=your_vercel_token
phantom sync --platform vercel --project prj_abc123
```

This pushes all vault secrets to the `production` and `preview` environments of the specified project.

### Persistent configuration via `.phantom.toml`

Add a `[[sync]]` block to your `.phantom.toml`:

```toml
[[sync]]
platform = "vercel"
token_env = "VERCEL_TOKEN"
project_id = "prj_abc123"
targets = ["production", "preview"]
```

`token_env` names the environment variable that holds your Vercel API token. Phantom reads it at sync time — the token is not stored in the config file.

`targets` controls which Vercel environments receive the secrets. Valid values are `production`, `preview`, and `development`. Defaults to `["production", "preview"]` if omitted.

Once configured, syncing is one command:

```bash
phantom sync
```

To sync only to Vercel when you have multiple platforms configured:

```bash
phantom sync --platform vercel
```

---

## Railway

### One-time run without configuration

```bash
export RAILWAY_TOKEN=your_railway_token
phantom sync --platform railway --project proj_abc123
```

### Persistent configuration via `.phantom.toml`

```toml
[[sync]]
platform = "railway"
token_env = "RAILWAY_TOKEN"
project_id = "proj_abc123"
environment_id = "production"
service_id = "svc_abc123"
```

`environment_id` defaults to `"production"` if omitted. `service_id` is optional — if omitted, secrets are set at the project level.

---

## Filtering with `--only`

Push a subset of secrets by passing one or more `--only` patterns:

```bash
# Push only secrets whose names start with STRIPE_
phantom sync --only "STRIPE_*"

# Push exactly DATABASE_URL and REDIS_URL
phantom sync --only DATABASE_URL --only REDIS_URL
```

Patterns are matched as shell globs against secret names. `--only` can be repeated.

You can also set per-target filters in `.phantom.toml` using the `only` field:

```toml
[[sync]]
platform = "vercel"
token_env = "VERCEL_TOKEN"
project_id = "prj_frontend"
only = ["NEXT_PUBLIC_*", "STRIPE_PUBLISHABLE_KEY"]

[[sync]]
platform = "vercel"
token_env = "VERCEL_TOKEN"
project_id = "prj_backend"
only = ["STRIPE_SECRET_KEY", "DATABASE_URL", "REDIS_URL"]
```

When `--only` is passed on the command line and the target also has an `only` list in the config, the two lists are merged — a secret passes if it matches any pattern from either source.

---

## Multiple targets

You can have multiple `[[sync]]` blocks — they are processed in order:

```toml
[[sync]]
platform = "vercel"
token_env = "VERCEL_TOKEN"
project_id = "prj_abc123"

[[sync]]
platform = "railway"
token_env = "RAILWAY_TOKEN"
project_id = "proj_def456"
environment_id = "production"
```

`phantom sync` runs all targets. `phantom sync --platform vercel` runs only matching blocks.

---

## MCP note

The `phantom_sync` MCP tool is read-only — it shows sync configuration and which secrets would be pushed, but does not execute any API calls. Actual sync requires running `phantom sync` in a terminal. This is intentional: sync writes to production infrastructure and should require an explicit human action.

---

## Reference

- Getting started: [getting-started.md](./getting-started.md)
- Cloud vault sync (Phantom Cloud, not deployment platforms): [login.md](./login.md)
- Troubleshooting: [troubleshooting.md](./troubleshooting.md)
- Site: [https://phm.dev](https://phm.dev)
