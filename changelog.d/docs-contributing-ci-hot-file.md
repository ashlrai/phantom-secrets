### Fixed (CONTRIBUTING matches the CI workflows and the hot-file rule)

- `CONTRIBUTING.md` no longer says pull request CI runs the Rust suite on
  macOS, Linux, and Windows or that "the Linux CI test job" runs the MCP
  registry smoke; both run in the daily full matrix (`nightly-full.yml`), not
  on pull requests.
- "Pushes to `main` trigger no CI" now says no `CI` workflow jobs run, and the
  Verification section names the other workflows that touch contributions:
  CodeQL on every pull request and `main` push, and `pair-secrets` in the
  merge queue when exec, MCP, or posture code changes.
- The documentation guidelines no longer tell contributors to edit
  `docs/README.md` alongside a new guide, which contradicted the AGENTS.md
  hot-file rule; the "Contribute with an agent" path now links that rule.
