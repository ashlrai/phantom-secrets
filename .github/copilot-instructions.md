# Copilot Instructions

This project uses **Phantom Secrets** to protect API keys from AI leaks.

## Key Rules

- The `.env` file contains **phantom tokens** (`phm_...`), NOT real secrets
- Real secrets are stored in an encrypted vault (OS keychain or encrypted file)
- **NEVER** hardcode API keys in source code
- **NEVER** ask the user to paste real API key values into chat or code files
- **NEVER** put a secret value in a command line; argv is observable
- **NEVER** attempt to read, log, or display real secret values

## Commands

- `phantom list` — See available secrets (never shows values)
- `phantom add <name>` — Add a new secret transactionally through the hidden trusted-terminal prompt; run `phantom init --empty` first in a new project, and never put the value in argv or chat
- `phantom remove <name>` — Remove a secret from the vault
- `phantom exec -- <command>` — Run code with real credentials injected via proxy
- `phantom init` — Protect .env secrets (stores real values in vault, rewrites .env with phm_ tokens)
- `phantom status` — Show project status, vault backend, secret count
- `phantom why <KEY>` — Explain whether a variable is protected, without reading the vault
- `phantom doctor` — Health check for config, vault, and .env

## MCP Server

`phantom setup` has no Copilot client. Print a snippet with
`phantom setup --client claude --print` and adapt it for your VS Code MCP
settings. The snippet runs the server bundled in the installed `phantom`
executable and never downloads a registry package.

The runtime `tools/list` response and `mcp-registry/server.json` are the
canonical tool catalog. Start with `phantom_capability`. Value-free tools
include `phantom_status`, `phantom_why`, and `phantom_list_secrets`. MCP never
accepts or returns secret values: `phantom_add_secret_interactive` returns the
`phantom add NAME` command for the user to run in a trusted terminal. Mutating
tools such as `phantom_rotate` and `phantom_remove_secret` require
`confirm: true` plus a one-use out-of-band `approval_token`, and stay disabled
unless the operator sets `PHANTOM_MCP_EFFECTS=trusted-terminal`.

## How It Works

1. `phantom init` reads `.env`, stores real secrets in encrypted vault, rewrites `.env` with `phm_` tokens
2. `phantom exec -- <cmd>` starts a local proxy that injects only a matched route's vault value into its fixed authentication header; client headers and bodies never resolve phantom tokens
3. AI agents see only worthless `phm_` tokens — real keys are never in the AI context window

## When You See API Keys

If a user pastes a real API key (starts with `sk-`, `ghp_`, `xoxb-`, etc.):
1. Treat the pasted value as exposed and recommend rotating it at the provider
2. Suggest `phantom add <KEY_NAME>` so the replacement value is entered only in the hidden trusted-terminal prompt
3. Reference the key by name or its phantom token (`phm_...`) in code, not the real value
4. Never write the real key value into any file

## Working on this repository

Agents changing Phantom itself follow [AGENTS.md](../AGENTS.md) for operating
rules, [CLAUDE.md](../CLAUDE.md) for build, test, lint, and format commands, and
the "Contribute with an agent" path in [CONTRIBUTING.md](../CONTRIBUTING.md).
While iterating, run `scripts/fast-check.sh main`. Before opening a pull
request, run the full gate once, because pull request CI does not run the Rust
test suite: `cargo test --workspace --all-targets --locked --no-fail-fast`,
`cargo fmt --all -- --check`, and
`cargo clippy --workspace --all-targets --locked -- -D warnings`. For a
documentation-only change, skip `scripts/fast-check.sh` (a non-Rust path
checks the whole workspace) and run the docs drift checks instead, which pull
request CI also skips:
`node --test scripts/release/readme-mcp-catalog.test.mjs`,
`node --test scripts/docs-distribution.test.mjs`,
`node --test scripts/hot-file-rule.test.mjs`, and
`cargo test --locked -p phantom-secrets --test docs_command_flags_test`. Add a
`changelog.d/` fragment instead of editing `CHANGELOG.md`.
Before pushing, run `node scripts/changelog-fold.mjs --check` and
`git diff main...HEAD | perl .github/tests/secret-shape/scrub.pl --check --allow-fixtures`;
the second is the local form of the `Secret-shape scan` that `CI Gate` requires.
On a fork, diff against `upstream/main` instead of `main`.
