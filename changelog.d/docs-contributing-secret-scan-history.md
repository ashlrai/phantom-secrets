### Changed (docs: the source secret scan also scans branch history)

- The `Source secret scan` row of "Reproduce the pull request jobs locally" in
  `CONTRIBUTING.md` now lists every command the job runs: the
  `validate-gitleaks-ignore` test, the size and timeout flags on
  `gitleaks dir`, and the `gitleaks git` history scan. A new note explains
  that a token committed and then deleted on a branch still fails the job,
  and that the history scan needs a full clone, not a shallow one.
