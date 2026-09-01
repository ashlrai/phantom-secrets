# Copilot Instructions

This project uses **Phantom Secrets** to protect API keys from AI leaks.

## Key Rules

- The `.env` file contains **phantom tokens** (`phm_...`), NOT real secrets
- Real secrets are stored in an encrypted vault (OS keychain or encrypted file)
- **NEVER** hardcode API keys in source code
- **NEVER** ask the user to paste real API key values into code files
- **NEVER** attempt to read, log, or display real secret values

## Commands

- `phantom list` — See available secrets (never shows values)
- `phantom add <name>` — Add a new secret transactionally through the hidden trusted-terminal prompt; run `phantom init --empty` first in a new project, and never put the value in argv or chat
- `phantom remove <name>` — Remove a secret from the vault
- `phantom exec -- <command>` — Run code with real credentials injected via proxy
- `phantom init` — Protect .env secrets (stores real values in vault, rewrites .env with phm_ tokens)
- `phantom status` — Show project status, vault backend, secret count
- `phantom doctor` — Health check for config, vault, and .env

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
