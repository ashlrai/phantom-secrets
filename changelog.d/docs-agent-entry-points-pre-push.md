### Changed (every agent entry point lists the pre-push checks)

- `CLAUDE.md`, `llms.txt`, `docs/llms.txt`, `docs/llms-full.txt`, and
  `.github/copilot-instructions.md` now name the two pre-push checks from
  `CONTRIBUTING.md`: `node scripts/changelog-fold.mjs --check` and the local
  form of the required `Secret-shape scan`. Before, only `CONTRIBUTING.md` and
  `AGENTS.md` listed them, so an agent starting from another entry point could
  push a malformed fragment or a token-shaped string.
