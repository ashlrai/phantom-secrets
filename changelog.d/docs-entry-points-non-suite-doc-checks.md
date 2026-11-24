### Changed (agent entry points name the doc checks the suite search misses)

- Every agent entry point (`AGENTS.md`, `README.md`, the three `llms` guides, `.cursorrules`, `.github/copilot-instructions.md`, `.devin/wiki.json`, and the pull request template) now names `bash scripts/test-docs-agents.sh` and `node scripts/freshness/check.mjs`, the two doc checks that the `git grep` suite lookup misses, matching `CLAUDE.md` and `CONTRIBUTING.md`. `scripts/agent-entry-points-pre-push.test.mjs` guards it.
