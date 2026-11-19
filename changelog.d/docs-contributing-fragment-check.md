### Changed (contributors validate changelog fragments before pushing)

- `changelog.d/README.md` now asks contributors to run
  `node scripts/changelog-fold.mjs --check` before pushing. Pull request and
  merge-queue CI do not validate fragments; only the daily full run does, so a
  malformed fragment could merge and turn that run red.
