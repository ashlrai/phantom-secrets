### Changed (docs: llms-full CLI commands)

- The CLI Commands list in `docs/llms-full.txt` now matches the CLI source.
  `phantom setup` describes all five clients and its `--print`, `--status`,
  `--dry-run`, `--replace`, `--undo`, and `--audit-mode` flags instead of
  "Claude Code only". The list adds `phantom agent status`, the `phantom audit`
  subcommands it was missing (`stats`, `anomalies`, `hotspots`, `incidents`,
  `alerts`, `analytics`, `export`, `export-range`, `report`, `feed`), and the
  flags it did not mention on `exec`, `list`, `add`, `reveal`, `status`,
  `check`, `pull`, `env`, `copy`, `import`, `validate`, `audit show`, and
  `audit verify`.
