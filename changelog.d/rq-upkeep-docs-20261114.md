### Changed (documentation index)

- `docs/README.md` now links the `phantom exec`, `phantom git-credential`,
  `phantom fleet-status`, `phantom audit feed` and `phantom agent doctor --json`
  references, the MCP secrets manager overview, the hybrid local quickstart and
  the public fact sheet, which were reachable only by file name.

### CI (documented flag drift)

- A docs-drift test fails when `README.md`, `llms.txt` or a `docs/*.md` file
  shows a `phantom <command> --flag` invocation whose flag the command does not
  define. Arguments after a bare `--` belong to the wrapped command and are
  not checked.
