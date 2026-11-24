### Fixed (docs)

- The Codex, Cursor, and Windsurf guides now say that `phantom setup --client`
  refuses to overwrite a `phantom` entry that differs from what it would write,
  and that `--replace` overwrites it after writing a backup and a manifest. The
  Codex guide had said that re-running setup merges a stale entry. The guides
  also show `--dry-run`, `--undo`, and `phantom setup --status`, as the Gemini
  CLI guide already did.
