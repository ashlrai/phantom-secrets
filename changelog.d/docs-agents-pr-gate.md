### Changed (agents see the same pull request gate as contributors)

- `AGENTS.md` "Build and test" now lists the locked, check-mode gate from
  `CONTRIBUTING.md` (`cargo fmt --all -- --check` and
  `cargo clippy --workspace --all-targets --locked -- -D warnings`), the
  `scripts/fast-check.sh main` iteration loop, and the two pre-push checks
  (changelog fragment validation and the local `Secret-shape scan`), and links
  the "Contribute with an agent" path.
