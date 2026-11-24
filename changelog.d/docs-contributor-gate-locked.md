### Changed (contributor gate commands match CI)

- README.md, AGENTS.md, CLAUDE.md, and the pull request template now give the
  docs drift test as `cargo test --locked -p phantom-secrets --test docs_command_flags_test`
  and the lint gate as `cargo clippy --workspace --all-targets --locked -- -D warnings`
  with `cargo fmt --all -- --check`, the same forms CONTRIBUTING.md and CI use.
  Without `--locked`, Cargo may rewrite `Cargo.lock`, which then widens
  `scripts/fast-check.sh` to the whole workspace and adds an unrelated file to
  the pull request.
