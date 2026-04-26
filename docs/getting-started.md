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

### `phantom add` / `phantom remove`

```bash
phantom add STRIPE_SECRET_KEY sk_live_abc123...
phantom remove STRIPE_SECRET_KEY
```

`add` stores the value and writes a phantom token to `.env`. `remove` deletes from the vault (`.env` token line is left; remove manually if desired).

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

# Pull from Vercel on a new machine
phantom pull --from vercel --project prj_abc123

# Railway
phantom sync --platform railway --project <id>
phantom pull --from railway --project <id> --environment production
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

### Claude Code (MCP)

```bash
claude mcp add phantom-secrets-mcp -- npx phantom-secrets-mcp
```

Or use `phantom setup` to configure it automatically alongside `.claude/settings.json`.

Once installed, Claude gains 17 Phantom tools and can manage secrets from inside the conversation. See [claude-code.md](./claude-code.md) for the full workflow.

### Cursor

Add in **Settings > Features > MCP Servers**:

| Field | Value |
|-------|-------|
| Name | `phantom` |
| Command | `npx` |
| Args | `phantom-secrets-mcp` |

Then run your project with `phantom exec -- cursor .` so the proxy is active.

### Windsurf

Add to your MCP configuration file:

```json
{
  "mcpServers": {
    "phantom": {
      "command": "npx",
      "args": ["phantom-secrets-mcp"]
    }
  }
}
```

### OpenAI Codex

Add to `~/.codex/config.json`:

```json
{
  "mcpServers": {
    "phantom": {
      "command": "npx",
      "args": ["phantom-secrets-mcp"]
    }
  }
}
```

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

No. Phantom tokens are safe for AI to read. They're random strings that are meaningless without the proxy. After `phantom init`, you can explicitly allow `.env` in Claude Code's settings — `phantom setup` does this automatically.

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
- [GitHub repository](https://github.com/ashlrai/phantom-secrets) — source, issues, releases
- [phm.dev](https://phm.dev) — pricing, cloud sync, team features
