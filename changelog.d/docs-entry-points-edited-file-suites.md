### Changed (contributor docs)

- Every agent entry point (`AGENTS.md`, `CLAUDE.md`, `README.md`, the three
  `llms.txt` files, the two site `llms*.txt` copies, `.cursorrules`, the
  Copilot instructions, and the DeepWiki outline) now tells a docs-only
  contributor to run every suite that reads the edited file, including those
  in `apps/web/tests/`, and shows the `git grep` command that lists them.
  `scripts/agent-entry-points-pre-push.test.mjs` checks that each one keeps it.
