### Changed (every agent entry point names the docs drift checks)

- `llms.txt`, `docs/llms.txt`, `docs/llms-full.txt`, `.cursorrules`,
  `.github/copilot-instructions.md`, `.devin/wiki.json`, and step 3 of
  "Contribute with an agent" in `CONTRIBUTING.md` now list the four docs
  drift checks that pull request CI skips, and tell a documentation-only
  change to run them instead of `scripts/fast-check.sh`. Before, only
  `AGENTS.md`, `CLAUDE.md`, the README, and the pull request template named
  them. `scripts/agent-entry-points-pre-push.test.mjs` now checks every entry
  point for all four commands.
