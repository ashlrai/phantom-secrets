### Changed (agent entry points name the local Rust test gate)

- `.cursorrules` and `.devin/wiki.json` now tell agents that pull request CI
  does not run the Rust test suite and give the full local gate, matching the
  Copilot instructions. The README's agent section names the exact
  `cargo test` command, and `scripts/agent-entry-points-pre-push.test.mjs`
  checks that every agent entry point says the Rust tests are a local step.
