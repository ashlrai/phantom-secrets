# Getting Started with Phantom

## TL;DR

```bash
brew tap ashlrai/phantom
brew trust --formula ashlrai/phantom/phantom
brew install ashlrai/phantom/phantom   # reviewed v0.7.3 macOS release
phantom init               # protects your .env
phantom agent doctor       # verify the repo is safe for AI agents
phantom exec -- claude     # run Claude Code with real secrets injected by proxy
```

That install example is for macOS. Linux and Windows users should select and
verify the exact `v0.7.3` GitHub asset below.

That's the local setup. Keep agent dotenv reads denied and launch supported API
work through `phantom exec`; Phantom reduces credential exposure, but it does
not control unmanaged files, other processes, provider logs, or every tool an
agent may invoke.

---

## What Phantom actually does

Phantom replaces detected API keys in your `.env` with random 256-bit tokens (`phm_...`) and stores the real values in the available OS credential store or encrypted-file fallback. When you run `phantom exec -- <cmd>`, a local HTTP reverse proxy starts on `127.0.0.1`, supported service SDKs are redirected through implemented `*_BASE_URL` variables, and the proxy session is authenticated with a fresh `PHANTOM_PROXY_TOKEN`. CLI-generated SDK URLs include the token as a local `/_phantom/<token>/` path segment; header-aware clients can set `PHANTOM_PROXY_HEADER_AUTH_ONLY=1` and send `x-phantom-proxy-token` instead. The proxy removes its local auth token before forwarding, replaces session tokens only in allowed headers and body fields, then forwards over TLS to the configured API endpoint. Agents can use value-blind MCP metadata without dotenv read access.

All request bodies are accepted into a bounded buffer before the upstream call,
so an oversized body fails with HTTP 413 before any partial mutation reaches a
provider. Text/form bodies retain whole-body token replacement; JSON bodies use
field-level scoping so values in fields such as `prompt` or `messages` are not
substituted. SSE/streaming responses remain streamed through content-aware
response scrubbing.

For a detailed breakdown of assets protected, threat actors, mitigations, and known gaps, see [THREAT_MODEL.md](../THREAT_MODEL.md).

---

## Install

### Homebrew (macOS, reviewed v0.7.3)

```bash
brew tap ashlrai/phantom
brew trust --formula ashlrai/phantom/phantom
brew install ashlrai/phantom/phantom
```

The formula installs both `phantom` and `phantom-mcp` from the immutable
[`v0.7.3` release](https://github.com/ashlrai/phantom-secrets/releases/tag/v0.7.3).

### Exact GitHub assets (Linux and Windows)

| Platform | `v0.7.3` archive | Published checksum |
|---|---|---|
| Linux x86_64 | [`phantom-x86_64-unknown-linux-gnu.tar.gz`](https://github.com/ashlrai/phantom-secrets/releases/download/v0.7.3/phantom-x86_64-unknown-linux-gnu.tar.gz) | [`sha256`](https://github.com/ashlrai/phantom-secrets/releases/download/v0.7.3/phantom-x86_64-unknown-linux-gnu.tar.gz.sha256) |
| Linux ARM64 | [`phantom-aarch64-unknown-linux-gnu.tar.gz`](https://github.com/ashlrai/phantom-secrets/releases/download/v0.7.3/phantom-aarch64-unknown-linux-gnu.tar.gz) | [`sha256`](https://github.com/ashlrai/phantom-secrets/releases/download/v0.7.3/phantom-aarch64-unknown-linux-gnu.tar.gz.sha256) |
| Windows x64 | [`phantom-x86_64-pc-windows-msvc.zip`](https://github.com/ashlrai/phantom-secrets/releases/download/v0.7.3/phantom-x86_64-pc-windows-msvc.zip) | [`sha256`](https://github.com/ashlrai/phantom-secrets/releases/download/v0.7.3/phantom-x86_64-pc-windows-msvc.zip.sha256) |
| Windows ARM64 | [`phantom-aarch64-pc-windows-msvc.zip`](https://github.com/ashlrai/phantom-secrets/releases/download/v0.7.3/phantom-aarch64-pc-windows-msvc.zip) | [`sha256`](https://github.com/ashlrai/phantom-secrets/releases/download/v0.7.3/phantom-aarch64-pc-windows-msvc.zip.sha256) |

Download the archive and its sidecar, then verify before extraction. Use
`sha256sum -c <archive>.sha256` on Linux. On Windows, compare
`Get-FileHash -Algorithm SHA256 <archive>` with the sidecar. Put both extracted
executables on `PATH`.

### Build the exact release source

```bash
git clone https://github.com/ashlrai/phantom-secrets.git
cd phantom-secrets
git checkout cffd0f29ab85a45358f011fdcfd40667d576c420
cargo build --release --locked --bin phantom --bin phantom-mcp
```

The full SHA above is the source commit resolved by `v0.7.3`. Do not treat an
unpinned registry install as that release. As verified on 2026-08-31, npm and
the MCP Registry publish `0.6.0`, while crates.io publishes `0.5.1`; those are
older distribution tracks.

### Verify

```bash
phantom --version
# phantom 0.7.3
```

---

## First run: representative terminal output

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
OPENAI_API_KEY=phm_a7f3b9e2c4d1f8a3b6e9d2c5f8a1b4e7a7f3b9e2c4d1f8a3b6e9d2c5f8a1b4e7
ANTHROPIC_API_KEY=phm_d4e7a0b3c6f9e2d5a8c1b4f7e0d3a6c9d4e7a0b3c6f9e2d5a8c1b4f7e0d3a6c9
DATABASE_URL=phm_b1c4d7e0a3f6b9c2d5e8a1b4c7d0e3f6b1c4d7e0a3f6b9c2d5e8a1b4c7d0e3f6
NODE_ENV=development
PORT=3000
```

Non-secret values (`NODE_ENV`, `PORT`) are left untouched. If your `.env` is at a non-standard path:

```bash
phantom init --from .env.local
```

`phantom init` does not create a plaintext project backup. Keep an independent
provider or password-manager recovery source, or use Phantom's encrypted
export below. `phantom unwrap` is unrelated to secret recovery: it only restores
`package.json` scripts previously changed by `phantom wrap`.

Connection strings such as `DATABASE_URL` are detected, vaulted, and replaced
in dotenv files, but they are **not proxied**. `phantom exec` fails closed when a
protected connection string is present because injecting the real URL into the
child environment would put the credential back inside the agent boundary. A
protocol-aware database broker is planned; until then, split API-key work from
database work or use a separately approved trusted-terminal workflow.

---

## Core commands

### `phantom init`

Reads `.env`, stores real secrets in the OS keychain, rewrites `.env` with phantom tokens, creates `.phantom.toml`. Safe to re-run: new secrets are added, existing phantom tokens are preserved.

```bash
phantom init
phantom init --from .env.local
```

**Multi-project — process eligible repos found by the bounded workspace scan:**

```bash
phantom init --all ~/code --dry-run    # preview which repos would be touched
phantom init --all ~/code              # process the exact repos shown by dry-run
phantom init --all ~/code --jobs 8     # run up to 8 repos concurrently (default: 4)
```

`--all` scans at most five directory levels for repositories containing a
supported dotenv filename and stops descending below the first matching
repository. It skips already-protected repositories, dot-directories, and
known dependency/build directories. Always review `--dry-run`; deeper or
nested repositories may require their own invocation. A progress bar shows
live status, and `PHANTOM_INIT_JOBS` can set the default parallelism.

### `phantom add` / `phantom remove`

```bash
# Interactive prompt — value is read silently from the terminal (no echo):
phantom add STRIPE_SECRET_KEY

# Pipe the value from a secret manager or CI helper (no tty required):
echo "$SECRET_VALUE" | phantom add STRIPE_SECRET_KEY --stdin
op read "op://Prod/Stripe/key" | phantom add STRIPE_SECRET_KEY --stdin

phantom remove STRIPE_SECRET_KEY
```

`add` stores the value and writes a phantom token to `.env`. It prompts silently so the secret never enters shell history or the process list. Positional secret values are rejected; use `--stdin` for non-interactive or CI input. `remove` deletes from the vault (`.env` token line is left; remove manually if desired).

### `phantom rotate`

Regenerates all project phantom tokens without changing the real secrets. A
`phm_` value is not accepted by the upstream provider, but an exposed mapping
should still be rotated because an authenticated active Phantom proxy is the
component that can resolve it.

```bash
phantom rotate
```

### `phantom cloud push` / `phantom cloud pull`

Back up and restore your vault on the same keychain machine using client-side
encryption. The cloud vault API receives ciphertext rather than decrypted secret
values; client, endpoint, account, and OS-keychain security remain part of the
trust boundary. Phantom does not currently transfer or recover the machine-local
cloud encryption key.

```bash
phantom login              # GitHub OAuth, once per device
phantom cloud push         # upload encrypted vault
phantom cloud pull         # restore where the original cloud key is available
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

# Preview without decrypting values or touching platform APIs
phantom sync --platform vercel --project prj_abc123 --dry-run --json

# Pull from Vercel with authorized provider access
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

Scans supported dotenv files for heuristically detected secrets. With
`--staged`, it also checks staged dotenv content and a bounded set of
hardcoded-key prefixes on added lines. Use it as one pre-commit layer, not as a
complete repository secret scanner.

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

### `phantom agent`

One command answers whether this repo is ready for autonomous AI coding tools.

```bash
phantom agent doctor          # human-readable readiness view
phantom agent report --json   # stable JSON for automation and CI
phantom agent setup --dry-run # preview safe setup changes
phantom agent setup --apply   # initialize safe defaults
```

The readiness engine checks `.env` files, `.phantom.toml`, vault access, unprotected secrets, `.env.example`, `.gitignore`, MCP client wiring, package script wrapping, pre-commit protection, audit status, cloud login, team state, and sync targets. It returns one state: `unsafe`, `protected`, `verified`, `team-ready`, or `compliance-ready`.

### `phantom reveal`

Print a real secret value to stdout. Blocked in non-interactive contexts by default.

```bash
phantom reveal OPENAI_API_KEY
phantom reveal OPENAI_API_KEY --clipboard   # trusted terminal + exact typed confirmation
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

Install both `v0.7.3` release binaries before setup. Released `v0.7.3` normally
records the running `phantom` executable with `mcp serve`; if that executable
cannot be resolved, it looks for the local standalone `phantom-mcp`. Its final
legacy fallback is unpinned `npx -y phantom-secrets-mcp`, which currently
resolves an older registry track. Do not rely on that path: keep both verified
release binaries installed and inspect the generated entry. Current main removes
the registry fallback and fails closed when neither local runtime is executable;
that hardening is not part of `v0.7.3` and awaits a later release. For Claude
Code, setup removes legacy Phantom-managed dotenv read grants and preserves deny
rules; agents use value-blind MCP inventory instead. See
[claude-code.md](./claude-code.md) for the full workflow. Runtime MCP `tools/list`
is the canonical catalog.

Restart the AI tool after running `phantom setup` so it picks up the new config.

Run `phantom agent doctor` after setup to confirm the repo is ready before handing work to Claude Code, Codex, Cursor, Windsurf, or another agent.

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

Each log entry is chained with HMAC-SHA256 and a signed head checkpoint. `phantom audit verify` detects malformed lines, modified or inserted entries, sequence gaps, prefix deletion, and log tail/head mismatches. It cannot prove the whole log and checkpoint were both deleted without an external backup or checkpoint.

---

## Encrypted backup and recovery

From an attached terminal, Phantom reads the backup passphrase without echoing
it or placing it in command-line arguments. Export asks for confirmation;
import reads the same passphrase once:

```bash
phantom export --output phantom-backup.enc
phantom import phantom-backup.enc
```

For automation on non-Windows platforms, provide a dedicated passphrase through
a bounded private file. On Unix, the file must be mode `0600` or stricter;
symlinks and non-regular files are rejected. `--passphrase-file` fails closed on
Windows pending no-reparse handle and effective private-ACL verification; use
the attached hidden terminal prompt there.

```bash
chmod 600 /secure/path/phantom-backup.pass
phantom export --output phantom-backup.enc \
  --passphrase-file /secure/path/phantom-backup.pass
phantom import phantom-backup.enc \
  --passphrase-file /secure/path/phantom-backup.pass
```

The output path must be new. Phantom never overwrites an existing file or
symlink and creates the encrypted archive atomically, with mode `0600` on Unix
and the containing directory's inherited ACL on Windows. Store the archive and
its passphrase separately. The former `--passphrase` argv option is retained
only to return a migration error because process inspection and shell history
can expose command-line arguments.

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
`phantom exec` uses the passphrase only in its trusted parent process, then
removes `PHANTOM_VAULT_PASSPHRASE` from both proxied and direct child
environments. Commands launched manually from the same shell still inherit the
export, so avoid launching agents outside `phantom exec` while it is set.

### An older registry-based install command fails

The reviewed binaries ship from the immutable `v0.7.3` GitHub Release, not the
older registry tracks. Download and verify the platform asset above, or build
the exact tagged source:

```bash
git clone https://github.com/ashlrai/phantom-secrets.git
cd phantom-secrets
git checkout cffd0f29ab85a45358f011fdcfd40667d576c420
cargo build --release --locked --bin phantom --bin phantom-mcp
```

The full SHA above is the source commit resolved by `v0.7.3`.

### Claude Code cannot read `.env` after setup — is this broken?

No. A `phm_` value is not a provider credential, but keeping dotenv reads
denied also protects unmanaged sibling files and backups created by other
tools. It also reduces exposure of mappings that an authenticated active
Phantom proxy could resolve. `phantom setup --client claude` wires MCP while
removing legacy Phantom-managed dotenv read grants; agents use value-blind
metadata instead.

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
