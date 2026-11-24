### Changed (docs)

- `CONTRIBUTING.md` "Making a change" now matches the fork path: branch from
  `upstream/main` in a fork, then add a `changelog.d/` fragment, run the two
  pre-push checks, and record the commands in the pull request template.
- `.github/copilot-instructions.md` lists the `scripts/fast-check.sh` iteration
  step, the full test, format, and Clippy gate, and the changelog fragment rule
  alongside the pre-push checks.
