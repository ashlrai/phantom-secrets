### Added (docs)

- `docs/gemini-cli.md` is a per-client guide for Gemini CLI, matching the
  Claude Code, Codex, Cursor, and Windsurf guides. It covers
  `phantom setup --client gemini` (alias `gemini-cli`), what setup merges into
  `~/.gemini/settings.json`, the `--print`, `--dry-run`, `--replace`, `--undo`,
  and `--status` options, the built-in `google_ai` route for `GEMINI_API_KEY`,
  the MCP effect gates, and troubleshooting. AGENTS.md links it from the
  per-client setup row, and `scripts/client-setup-docs.test.mjs` now checks
  the guide's config example and effect-gate wording.
