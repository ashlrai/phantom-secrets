# Contributing to Phantom

Thanks for your interest in contributing to Phantom! Here's how to get started.

## Development Setup

```bash
# Clone the repo
git clone https://github.com/ashlrai/phantom-secrets.git
cd phantom-secrets

# Build
cargo build --workspace

# Run tests
cargo test --workspace

# Lint (must pass with zero warnings)
cargo clippy --all-targets -- -D warnings

# Format
cargo fmt --all
```

## Project Structure

```
crates/
  phantom-cli/     CLI binary (30 commands)
  phantom-core/    Config, .env parsing, tokens, auth, cloud client
  phantom-vault/   Encrypted vault (keychain + file backends)
  phantom-proxy/   HTTP reverse proxy with streaming
  phantom-mcp/     MCP server for Claude Code (25 tools)
apps/
  web/             Next.js backend + landing page (phm.dev)
```

## Making Changes

1. Fork the repo and create a branch from `main`
2. Make your changes
3. Ensure `cargo test`, `cargo clippy`, and `cargo fmt --check` all pass
4. Open a pull request

## What to Contribute

- Bug fixes (check [Issues](https://github.com/ashlrai/phantom-secrets/issues))
- New service auto-detection patterns (in `crates/phantom-core/src/config.rs`)
- Documentation improvements
- Test coverage
- Platform support (Windows improvements, new Linux distros)

## Code Guidelines

- All code must pass `cargo clippy -- -D warnings`
- Tests go in `#[cfg(test)] mod tests` within source files
- Use `thiserror` for library crates, `anyhow` for CLI
- Secrets must be zeroized from memory after use
- Proxy binds to 127.0.0.1 only

## Questions?

Open a [Discussion](https://github.com/ashlrai/phantom-secrets/discussions) or file an [Issue](https://github.com/ashlrai/phantom-secrets/issues).
