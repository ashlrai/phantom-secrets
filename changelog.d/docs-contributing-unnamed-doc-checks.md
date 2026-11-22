### Changed (contributor docs)

- `CONTRIBUTING.md` and `CLAUDE.md` now name the two doc checks that the
  `git grep -l -F <file-name> -- '*.test.*'` search misses and that pull
  request CI does not run: `bash scripts/test-docs-agents.sh` after editing
  `docs/agents.md`, and `node scripts/freshness/check.mjs` after editing a
  file with a generated `fresh:begin` version block.
