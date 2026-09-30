# Recipe: a Phantom secret gate in GitHub Actions

[phantom-secret-gate.yml](phantom-secret-gate.yml) is a pull-request check you
can copy into `.github/workflows/`. It needs no vault and no secrets. It
installs the checksum-verified v0.7.9 release and runs two steps:

1. `phantom check`: fails if a committed dotenv file (`.env`, `.env.local`,
   `.env.development`, `.env.production`, or the configured `dotenv_path`)
   holds a raw value instead of a `phm_` placeholder.
2. `git reset --soft <PR base>` then `phantom check --staged`: stages exactly
   the lines the pull request adds and scans them the way the local pre-commit
   hook scans a commit. A hardcoded `sk-…`, `sk_live_…`, `ghp_…`,
   `github_pat_…`, `glpat-…`, `xox[bp]-…` or `AKIA…` value fails the job.

The failure names the file and the key name. It never prints the value.

## Run the recipe

[run.mjs](run.mjs) replays the workflow's two steps in a local git repository
with a fake key: a clean PR passes, a PR that hardcodes a key fails, and a PR
that commits a raw `.env.production` fails.

```text
node examples/github-actions/run.mjs --phantom /absolute/path/to/phantom
```

```text
PASS a Phantom-protected main branch passes `phantom check`
PASS a clean pull request passes `phantom check --staged` against its base
PASS a pull request that hardcodes a key fails `phantom check --staged`
PASS a pull request that commits a raw dotenv value fails `phantom check`
COMPLETE: GitHub Actions secret gate recipe (4 checks)
```

This recipe passes against both the v0.7.9 release and the workspace build.
The install step in the workflow was also run as written on Linux x86_64
(`gh release download`, `sha256sum -c`, `phantom --version` → `phantom 0.7.9`).

## Scope

This is a leak gate. It does not inject secrets into CI jobs. For deploy-time
secrets, sync them to your platform first (`phantom sync --platform vercel` or
`railway`) as described in [docs/ci-cd.md](../../docs/ci-cd.md). Headless
Phantom Cloud pulls are not supported yet. For ARM64 or non-Linux runners,
select the matching release asset.
