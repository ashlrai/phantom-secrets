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

Modular Rust workspace with a shipped secret-protection product and separate
fail-closed governed-execution foundations:

- **phantom-core** — Config (.phantom.toml), .env parsing/rewriting, phantom token generation (256-bit CSPRNG, `phm_` prefix), error types
- **phantom-vault** — `VaultBackend` trait with OS keychain (macOS Keychain, Linux Secret Service, Windows Credential Manager) and encrypted file fallback. Argon2id parameters hardened to OWASP balanced (m=64 MiB, t=3, p=1) with legacy-default fallback for older vaults
- **phantom-proxy** — HTTP reverse proxy on 127.0.0.1. It authenticates and matches exact routes, discards client control of the route auth header, injects only the route-owned vault value there, and forwards client bodies byte-for-byte under a hard size cap. Client headers/bodies never resolve `phm_` tokens. Uses `hyper` for server and `reqwest` for outbound HTTPS; response streaming/SSE is preserved through scrubbing.
- **phantom-cli** — `clap`-based CLI for init, proxy execution, diagnostics, sync, teams, audit, validation, provider design foundations, and trusted-terminal workspace setup. Live provider issuance/rotation is hard-denied before credential/network access in 0.7.5. Use `phantom --help` as the canonical command inventory. Plaintext JSON export is disabled; reveal requires an attached terminal and exact typed confirmation.
- **phantom-mcp** — MCP server for Claude Code, Cursor, Windsurf, Codex. Uses `rmcp` 1.3 SDK and stdio transport. Exposes core vault/diagnostic/cloud/team tools plus advanced audit, validation, rotation, expiry, leak-incident, and compliance workflows. The exact catalog is declared in `crates/phantom-mcp/src/server.rs`.
- **governed-execution foundations** — `phantom-workspace` provides the active value-blind Unix setup transaction. `phantom-authority`, `phantom-locus-contract`, `phantom-broker`, `phantom-runtime`, `phantom-session`, and `phantom-evidence` remain fail closed for production execution.

### How the proxy works

The proxy is a **reverse proxy with URL rewriting**, NOT a forward/CONNECT proxy. This avoids MITM/CA certificate issues:

1. `phantom exec` sets `OPENAI_BASE_URL=http://127.0.0.1:PORT/openai` (and similar for other services)
2. API client code sends HTTP to localhost proxy instead of real HTTPS endpoint
3. Proxy authenticates and matches an exact route, then injects the route-owned vault value only into its fixed auth header; client headers/bodies remain unresolved
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
