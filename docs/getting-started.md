# Getting Started with Phantom

## TL;DR

```bash
npx phantom-secrets init   # installs Phantom and protects your .env
phantom exec -- claude     # run Claude Code with real secrets injected by proxy
```

That's it. Your AI tool never sees a real key again.

---

## What Phantom actually does

Phantom replaces real API keys in your `.env` with random 256-bit tokens (`phm_...`) and stores the real values in your OS keychain. When you run `phantom exec -- <cmd>`, a local HTTP reverse proxy starts on `127.0.0.1`. API SDKs are redirected to this proxy via `*_BASE_URL` environment variables; the proxy swaps phantom tokens for real credentials in request headers and body before forwarding over TLS to the actual API endpoint. The AI agent reads `.env`, gets only worthless tokens, and its logs and context windows contain nothing sensitive.

For `text/*` and `application/x-www-form-urlencoded` request bodies the proxy replaces tokens frame-by-frame without buffering the full payload (streaming token replacement). JSON bodies use a buffered path with field-level scoping to avoid substituting tokens that appear in non-secret fields such as `prompt` or `messages`. Full SSE/streaming responses (OpenAI, Anthropic) are preserved end-to-end.

For a detailed breakdown of assets protected, threat actors, mitigations, and known gaps, see [THREAT_MODEL.md](../THREAT_MODEL.md).

---

## Install

### npx (recommended — no global install required)

```bash
npx phantom-secrets init
```

Downloads the correct platform binary and runs `phantom init` in one step.

### npm global

```bash
npm install -g phantom-secrets
phantom init
```

### Homebrew (macOS)

```bash
brew tap ashlrai/phantom
brew install phantom
```

### Direct binary download

Download from [GitHub Releases](https://github.com/ashlrai/phantom-secrets/releases), extract, and place `phantom` on your `$PATH`.

### Verify

```bash
phantom --version
# phantom 0.5.1
```

---

## First run: exact terminal output

```
$ cd my-project
$ phantom init
-> Scanning .env...
-> Found 3 secret(s): OPENAI_API_KEY, ANTHROPIC_API_KEY, DATABASE_URL
-> Storing secrets in OS keychain...
ok  OPENAI_API_KEY stored
ok  ANTHROPIC_API_KEY stored
ok  DATABASE_URL stored
-> Rewriting .env with phantom tokens...
ok  .env updated
-> Writing .phantom.toml...
ok  Initialized. Run `phantom exec -- <cmd>` to start the proxy.
```

Your `.env` now contains:

```env
# Managed by Phantom -- do not edit phantom tokens manually
OPENAI_API_KEY=phm_a7f3b9e2c4d1f8a3b6e9d2c5f8a1b4e7
ANTHROPIC_API_KEY=phm_d4e7a0b3c6f9e2d5a8c1b4f7e0d3a6c9
DATABASE_URL=phm_b1c4d7e0a3f6b9c2d5e8a1b4c7d0e3f6
NODE_ENV=development
PORT=3000
```

Non-secret values (`NODE_ENV`, `PORT`) are left untouched. If your `.env` is at a non-standard path:

```bash
phantom init --from .env.local
```

---

## Core commands

### `phantom init`

Reads `.env`, stores real secrets in the OS keychain, rewrites `.env` with phantom tokens, creates `.phantom.toml`. Safe to re-run: new secrets are added, existing phantom tokens are preserved.

```bash
phantom init
phantom init --from .env.local
```

**Multi-project — protect every repo in a workspace at once:**

```bash
phantom init --all ~/code --dry-run    # preview which repos would be touched
phantom init --all ~/code              # run init in every git repo with a .env
phantom init --all ~/code --jobs 8     # run up to 8 repos concurrently (default: 4)
```

`--all` walks the directory, finds every git repo with one of `.env`, `.env.local`, `.env.development`, `.env.production`, etc., and runs init in each. Skips repos that already have `.phantom.toml`, plus `node_modules`, `target`, `dist`, `build`, and dot-dirs. A progress bar shows live status. The parallelism default can also be set via the `PHANTOM_INIT_JOBS` environment variable.

### `phantom add` / `phantom remove`

```bash
# Positional value (backward-compatible, but ends up in shell history):
phantom add STRIPE_SECRET_KEY sk_live_abc123...

# Interactive prompt — value is read silently from the terminal (no echo):
phantom add STRIPE_SECRET_KEY

# Pipe the value from a secret manager or CI helper (no tty required):
echo "$SECRET_VALUE" | phantom add STRIPE_SECRET_KEY --stdin
op read "op://Prod/Stripe/key" | phantom add STRIPE_SECRET_KEY --stdin

phantom remove STRIPE_SECRET_KEY
```

`add` stores the value and writes a phantom token to `.env`. When no positional value is given, phantom prompts silently on the terminal so the secret never enters your shell history. Use `--stdin` for non-interactive / CI use. `remove` deletes from the vault (`.env` token line is left; remove manually if desired).

### `phantom rotate`

Regenerates all phantom tokens without changing the real secrets. Use this if you suspect a token mapping was exposed (tokens are worthless without the proxy, but rotation is a clean reset).

```bash
phantom rotate
```

### `phantom cloud push` / `phantom cloud pull`

Sync your vault across machines. End-to-end encrypted — the server never sees plaintext.

```bash
phantom login              # GitHub OAuth, once per device
phantom cloud push         # upload encrypted vault
phantom cloud pull         # download and decrypt on another machine
```

### `phantom sync` / `phantom pull`

Push real secrets to a deployment platform, or pull them from one.

```bash
# Push to Vercel
phantom sync --platform vercel --project prj_abc123

# Push only Stripe secrets (glob pattern — avoids dev-only keys going to prod)
phantom sync --platform railway --project <id> --only "STRIPE_*"

# Multiple --only flags are OR-ed together
phantom sync --platform vercel --project prj_abc123 --only "STRIPE_*" --only "*_KEY"

# Pull from Vercel on a new machine
phantom pull --from vercel --project prj_abc123

# Railway
phantom sync --platform railway --project <id>
phantom pull --from railway --project <id> --environment production
```

You can also hard-code filters per `[[sync]]` block in `.phantom.toml` so that `phantom sync` (no flags) always respects them:

```toml
[[sync]]
platform     = "railway"
token_env    = "RAILWAY_TOKEN"
project_id   = "<id>"
only         = ["STRIPE_*", "SENDGRID_*"]   # never push DEV_* or DEBUG_* to prod
```

### `phantom check`

Scans `.env` files for unprotected secrets. Use as a pre-commit hook.

```bash
phantom check
# BLOCKED Unprotected secrets detected!
#   ! .env: OPENAI_API_KEY is not protected
# fix Run `phantom init`
```

Exit code 0 = clean. Exit code 1 = unprotected secrets found.

### `phantom doctor`

Health check for your setup: config validity, vault access, `.env` protection, `.gitignore` coverage, `.env.example`, pre-commit hook.

```bash
phantom doctor
phantom doctor --fix    # auto-fix safe issues
```

```
$ phantom doctor
pass: .phantom.toml found
pass: Config valid (project: a1b2c3d4)
pass: Vault backend: macOS Keychain
pass: 3 secret(s) in vault
pass: .env has 5 entries, all protected
pass: .env is in .gitignore
warn: No .env.example — team onboarding may be difficult
warn: No pre-commit hook installed

2 issue(s) found — use --fix to auto-fix
```

### `phantom reveal`

Print a real secret value to stdout. Blocked in non-interactive contexts by default.

```bash
phantom reveal OPENAI_API_KEY
phantom reveal OPENAI_API_KEY --clipboard   # copies and auto-clears after 30s
phantom reveal OPENAI_API_KEY --yes         # bypass interactive check (scripts/CI)
```

---

## Editor integrations

One command per AI client — Phantom writes the right config file in the right place:

```bash
phantom setup --client claude     # .claude/settings.local.json (project)
phantom setup --client cursor     # ~/.cursor/mcp.json
phantom setup --client windsurf   # ~/.codeium/windsurf/mcp_config.json
phantom setup --client codex      # ~/.codex/config.toml
phantom setup --client claude --print   # snippet to stdout for any other client
```

If `phantom-mcp` isn't on PATH, the writer falls back to `npx -y phantom-secrets-mcp` so the config still works on a fresh machine. For Claude Code specifically, `phantom setup --client claude` *also* allow-lists `.env` so Claude can read the (now-tokenized) file. See [claude-code.md](./claude-code.md) for the full workflow — the AI gains 25 Phantom MCP tools.

Restart the AI tool after running `phantom setup` so it picks up the new config.

---

## Audit log (opt-in)

For compliance or forensics, set `PHANTOM_AUDIT=1` to record every vault store/retrieve/delete to `~/.phantom/audit.log`:

```bash
export PHANTOM_AUDIT=1
phantom exec -- npm run dev
```

Each line is a JSON object with `ts`, `op`, `name` (the secret name — **never the value**), `process`, and `pid`. Off by default; turn on per-shell or in your `.envrc` / `.zprofile`.

### Viewing and verifying the log

```bash
# Print the last 50 events (default)
phantom audit show

# Filter by operation or secret name
phantom audit show --op vault.store --name OPENAI_API_KEY

# Follow the log live (like tail -f)
phantom audit tail

# Print the absolute path to the log file
phantom audit path

# Verify HMAC-SHA256 chain integrity — exits 1 if tampering detected
phantom audit verify
```

Each log entry is chained with HMAC-SHA256 so any deletion or modification of entries is detectable by `phantom audit verify`.

---

## Importing from other secret managers

Migrate secrets from Doppler, Infisical, dotenvx, 1Password, or a plain `.env` file without exposing values in your shell:

```bash
# Doppler: export secrets as JSON first, then import
phantom import --from doppler --file dump.json

# Infisical: export as .env, then import
phantom import --from infisical --file export.env

# dotenvx: import a plaintext .env (not an encrypted .env.vault)
phantom import --from dotenvx --file .env

# 1Password: export as JSON, then import
phantom import --from 1password --file 1p-export.json

# Plain .env file (same heuristics as phantom init)
phantom import --from env --file .env
```

After importing, run `phantom init` to replace any remaining plaintext secrets in your `.env` with phantom tokens.

Use `--force` to overwrite existing vault entries without prompting.

---

## Troubleshooting

### "No .phantom.toml found"

You haven't initialized in this directory.

```bash
phantom init
```

### API calls return 401 after setup

The proxy is not running or the `*_BASE_URL` variables aren't set. Always run your tool via `phantom exec`:

```bash
phantom exec -- node server.js
phantom exec -- claude
```

Check status:

```bash
phantom status
phantom doctor
```

### Keychain access prompt on macOS

Click "Always Allow" for the `phantom-secrets` entry. This appears once per application.

### Linux keychain unavailable / CI environments

Set a passphrase and Phantom falls back to an encrypted file vault:

```bash
export PHANTOM_VAULT_PASSPHRASE="$(openssl rand -hex 32)"
```

Store this passphrase as a CI secret. See `docs/ci-cd.md` for full GitHub Actions and Docker examples.

### `npx phantom-secrets` fails to download

The binary ships from GitHub Releases. Check your internet connection, then:

```bash
# Fallback: install from source
cargo install phantom-secrets
```

Or download the binary directly from [github.com/ashlrai/phantom-secrets/releases](https://github.com/ashlrai/phantom-secrets/releases).

### Claude Code reads `.env` and sees phantom tokens — is this broken?

No. Phantom tokens are safe for AI to read. They're random strings that are meaningless without the proxy. After `phantom init`, you can explicitly allow `.env` in Claude Code's settings — `phantom setup --client claude` does this automatically (or use `--client cursor|windsurf|codex` for other AI tools).

---

## Dashboard

Once you've run `phantom login` and `phantom cloud push`, you can see your projects, vault sizes, last sync, plan tier, and team membership at [phm.dev/dashboard](https://phm.dev/dashboard). It's read-only — every mutation still happens via the CLI — but it's useful for "wait, which projects do I have backed up?" moments.

```bash
$ phantom open
# Opens https://phm.dev/dashboard in your browser. Aliases:
# phantom open billing | team | docs | github | pricing
```

## Next steps

- [Claude Code integration](./claude-code.md) — MCP tools, workflow examples, what Claude can and cannot do
- [CI/CD setup](./ci-cd.md) — GitHub Actions, Docker, encrypted file vault
- [Troubleshooting](./troubleshooting.md) — extended issue reference
- [Threat model](../THREAT_MODEL.md) — assets, actors, mitigations, known gaps, cryptography summary
- [GitHub repository](https://github.com/ashlrai/phantom-secrets) — source, issues, releases
- [phm.dev](https://phm.dev) — pricing, cloud sync, team features
