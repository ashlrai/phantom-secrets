# Gemini CLI instructions

@./AGENTS.md

[AGENTS.md](AGENTS.md) is the canonical brief for every coding agent working in `phantom-secrets` (Codex, Claude Code, Cursor, GitHub Copilot, Gemini CLI, Grok, Devin, Aider, Windsurf, or a local model). The import above loads it. If your tool does not follow imports, read AGENTS.md before changing anything.

Quick reference (details and exceptions live in AGENTS.md and CONTRIBUTING.md):

- Toolchain: stable Rust
- Setup: `cargo build --workspace --locked`
- Test: `cargo test --workspace --all-targets --locked --no-fail-fast`
- Before opening a PR: `cargo fmt --all -- --check && cargo clippy --workspace --all-targets --locked -- -D warnings`
- Open a focused PR against the default branch; never force-push shared branches or bypass required checks.
- Fill in the optional "Agent used" line in the PR template so maintainers can see which tools contribute.
- Never commit secrets, tokens or personal data.
