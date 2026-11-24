### Changed (docs: llms.txt CLI surface matches the CLI source)

- `docs/llms.txt` now lists the flags each command accepts in the source,
  including `add --generate`, `exec --scrub-output`, `setup --undo`,
  `doctor --all`, `status --oneline` and `check --json`. The site's
  `apps/web/public/llms.txt` command list adds the five commands it left
  out: `redact`, `git-credential`, `fleet-status`, `leaks` and `crypto`.
