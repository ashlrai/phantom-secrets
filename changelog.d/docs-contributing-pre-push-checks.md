### Changed (contributors run the pre-push checks CI relies on)

- `CONTRIBUTING.md` now lists two pre-push checks in the contributor path: the
  changelog fragment check (`node scripts/changelog-fold.mjs --check`) and the
  local form of the required `Secret-shape scan` job, with the test-path rule
  for fake token values.
- The fragment heading list now matches `scripts/changelog-fold.mjs` (adds
  `Removed`, `Deprecated`, and `CI`), and the `scripts/fast-check.sh`
  description names the `scripts/test-sleep-budget.test.mjs` suite it runs.
