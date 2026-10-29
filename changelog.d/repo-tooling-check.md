### CI (repo tooling config validation)

- Added `scripts/check-repo-tooling.mjs` and `scripts/repo-tooling.test.mjs`:
  the validator locks in the invariants of the repo-tooling configs
  (`renovate.json`, `socket.yml`, `codecov.yml`, `.coderabbit.yaml`,
  `.sonarcloud.properties`) and the Scorecard/coverage workflow wiring —
  no automerge anywhere, release-age soak kept, Scorecard limited to its
  weekly schedule and dispatch, coverage restricted to `merge_group` and the
  nightly run and outside the CI Gate, every `uses:` pinned to a full commit
  SHA, and every referenced analysis/scrutiny path required to exist.
  `scripts/fast-check.sh` now runs it in the dev loop.
