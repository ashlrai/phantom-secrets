### Changed (docs)

- `docs/delegation-quickstart.md` no longer tells you to keep your own copy of
  a client config for rollback. Step 3 now describes what setup does for
  Codex, Cursor, Windsurf, and Gemini CLI: the `--dry-run` diff, the refusal
  of a differing `phantom` entry and `--replace`, the automatic backup and
  `~/.phantom/setup-manifest.json` record, and `phantom setup --undo`
  (`--apply` to perform it). It also names `--status` and says the Claude Code
  writer is previewed with `--print`. The recovery bullet for a wrong client
  config now points at `phantom setup --undo`.
