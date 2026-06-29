# Phantom — Development Guide

## Quick Reference

```bash
# Build
~/.cargo/bin/cargo build

# Test
~/.cargo/bin/cargo test

# Lint (must pass with zero warnings)
~/.cargo/bin/cargo clippy --all-targets -- -D warnings

# Format
~/.cargo/bin/cargo fmt --all

# Run CLI
~/.cargo/bin/cargo run -- <command>
```

Note: `~/.cargo/bin/` prefix is needed because cargo is not in PATH on this machine.

## Architecture

5-crate Rust workspace:

- **phantom-core** — Config (.phantom.toml), .env parsing/rewriting, phantom token generation (256-bit CSPRNG, `phm_` prefix), error types
- **phantom-vault** — `VaultBackend` trait with OS keychain (macOS Keychain, Linux Secret Service, Windows Credential Manager) and encrypted file fallback. Argon2id parameters hardened to OWASP balanced (m=64 MiB, t=3, p=1) with legacy-default fallback for older vaults
- **phantom-proxy** — HTTP reverse proxy on 127.0.0.1. Receives plaintext HTTP, replaces phantom tokens in headers/body with real secrets, forwards over TLS. Uses `hyper` for server, `reqwest` for outbound HTTPS. Streaming token replacement for `text/*` and `application/x-www-form-urlencoded` request bodies (frame-by-frame, 67-byte carry buffer for cross-chunk tokens); buffered path for JSON with field-level F9 scoping.
- **phantom-cli** — `clap`-based CLI binary. 33 commands: init (--from <file>, --all <DIR>, --dry-run, --jobs/-j N), exec, start, stop, list (--json), add (--stdin), remove, reveal, rotate, status, agent (report [--json], doctor, setup [--dry-run|--apply]), doctor (--fix), check (--staged, --runtime), sync (--only PATTERN), pull, env, setup (--client claude|cursor|windsurf|codex, --print), login, logout, cloud (push/pull/status), team (list/create/members/invite/key-publish/vault-push/vault-pull), export (--json --allow-plaintext), import (--from doppler|infisical|dotenvx|1password|env --file <path>, or legacy <FILE> --passphrase), audit (show [--last N] [--op OP] [--name NAME] [--json] / tail [--op] [--name] / path / verify), wrap, unwrap, watch, why, copy, open, upgrade, completion. `--help` is grouped: Setup · Daily use · Sync & teams · Maintenance
- **phantom-mcp** — MCP server for Claude Code, Cursor, Windsurf, Codex. Uses `rmcp` 1.3 SDK. Stdio transport. 25 tools: phantom_list_secrets, phantom_status, phantom_init, phantom_add_secret (deprecated; refuses plaintext), phantom_add_secret_interactive, phantom_remove_secret, phantom_rotate, phantom_copy_secret, phantom_cloud_push, phantom_cloud_pull, phantom_cloud_status, phantom_doctor, phantom_why, phantom_check, phantom_env, phantom_sync, phantom_wrap, phantom_unwrap, phantom_team_list, phantom_team_create, phantom_team_members, phantom_team_invite, phantom_team_key_publish, phantom_team_vault_push, phantom_team_vault_pull

### How the proxy works

The proxy is a **reverse proxy with URL rewriting**, NOT a forward/CONNECT proxy. This avoids MITM/CA certificate issues:

1. `phantom exec` sets `OPENAI_BASE_URL=http://127.0.0.1:PORT/openai` (and similar for other services)
2. API client code sends HTTP to localhost proxy instead of real HTTPS endpoint
3. Proxy scans headers + body for `phm_` tokens, replaces with real secrets from vault
4. Proxy forwards modified request over TLS to real endpoint (e.g., `api.openai.com`)

### Secret detection

`dotenv.rs::looks_like_secret()` uses heuristics to distinguish secrets from config:
- Key patterns: `*_KEY`, `*_SECRET*`, `*_TOKEN`, `*_PASSWORD`, `DATABASE_URL`, etc.
- Value patterns: `sk-*`, `ghp_*`, connection strings with `@`, high-entropy long strings
- Non-secrets left untouched: `NODE_ENV`, `PORT`, `DEBUG`, etc.

## Conventions

- All code must pass `cargo clippy -- -D warnings` and `cargo fmt --check`
- Tests go in `#[cfg(test)] mod tests` within source files, not separate test files
- Integration tests for proxy use `test_server.rs` (mock HTTP server that records requests)
- Error handling: `thiserror` for library crates, `anyhow` for CLI
- CLI output uses `colored` crate — prefix lines with `->`, `ok`, `!`, `warn`, etc.
- Secrets must be `zeroize`d from memory after use
- Proxy binds to 127.0.0.1 ONLY — never expose to network
- Audit log is opt-in: `PHANTOM_AUDIT=1` writes JSONL events for vault store/retrieve/delete to `~/.phantom/audit.log`. Schema records the secret **name** only — never the value. Each entry carries an HMAC-SHA256 over the previous entry's hash (chain rooted at a zero-hash). New audit hook points should call `phantom_core::audit::log(op, name)`. Use `phantom audit verify` to check chain integrity.
- Importers live in `phantom-core/src/importers/`. Each format (doppler, infisical, dotenvx, 1password, env) implements a parser that returns `BTreeMap<String, String>`. The CLI dispatcher is `phantom_core::importers::import_from(source, path)`.
