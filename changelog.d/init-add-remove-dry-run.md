### Added (`--dry-run` for `phantom init`, `phantom add`, and `phantom remove`)

- `phantom init --dry-run` prints the keys it would protect, the project
  files it would write, and the encrypted-file vault path it would create,
  then exits without creating a vault or changing any file. When
  `.claude/settings.local.json` or `.mcp.json` already exist, it prints
  `may update <path>` and does not take the project lock.
  `phantom init --all --dry-run` keeps its existing scan report.
  `phantom init --empty --dry-run` reports the config file and the empty
  vault it would create.
- `phantom add --dry-run` and `phantom remove --dry-run` print the key and
  the files that transaction would write without opening the vault, taking a
  project lock, or creating app-data directories. Plan lines use `would add`
  and `would remove`. They print `would add <name> (vault state not checked
  in dry run)` or `would remove <name> (vault state not checked in dry run)`,
  and `dotenv token check uses project config key names only (vault key names
  not checked in dry run)`, because vault key names cannot be listed without
  opening the vault. Config key names still drive the same dotenv token
  refusal a real run uses. Remove also applies the real dotenv mapping rules
  (exactly one phantom mapping for that name) and prints `would remove <name>
  (not in project config)` when `.phantom.toml` has no `[phantom.secrets]`
  entry for it. Add does not read a value. Remove does not ask for the
  trusted-terminal challenge and does not delete the vault entry. None of
  these previews print secret values.
