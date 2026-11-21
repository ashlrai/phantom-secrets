### Changed (issue forms point contributors at the pull request path)

- The GitHub issue chooser has a "Fix it yourself, with or without a coding
  agent" link to "Contribute with an agent" in `CONTRIBUTING.md`, and the
  documentation report form says a small, evidence-backed docs fix can go
  straight to a pull request with the docs drift checks run locally.
- `scripts/issue-templates.test.mjs` checks that both forms keep that link and
  that the `CONTRIBUTING.md` heading it targets still exists.
