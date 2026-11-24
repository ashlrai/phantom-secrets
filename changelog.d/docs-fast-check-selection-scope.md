### Changed (contributing: fast-check scope)

- `CONTRIBUTING.md`, `AGENTS.md`, `CLAUDE.md`, and the `llms.txt` files now
  state when `scripts/fast-check.sh` actually narrows its checks: only when
  every changed file is Rust source under a crate's `src/`. A doc, script,
  manifest, lockfile, `build.rs`, or test/fixture change checks the whole
  workspace, so docs-only contributors are told to skip it and run the drift
  checks instead. `CONTRIBUTING.md` also documents which changes each
  argument form covers (working tree and untracked files for `BASE`, commits
  only for `BASE HEAD`), matching `scripts/affected-crates.sh` and its
  fixture tests.
