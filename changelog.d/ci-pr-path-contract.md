### CI (pull-request runner-capacity contract; reworks #562)

- Added `scripts/ci/pr-path-contract.test.mjs`, a read-only contract over
  `ci.yml`, `codeql.yml` and `nightly-full.yml` locking the runner-capacity
  split #562 asked for in its current (stronger) form: pull requests and the
  merge queue run only the seconds-fast job set, `ci.yml` has no `push`
  trigger, the daily matrix still reaches every OS leg through
  `nightly-full.yml`, `CI Gate` can never be left pending, and CodeQL on PRs
  scans only languages the diff touched. Superseded runs still cancel.
- Reconciled `scripts/ci/daily-matrix.md` with the post-#576 workflow shape:
  the documented `affected_only` wiring now gates `windows-arm-source-check`
  and `coverage` on `os_matrix`, and flags the gate change the patch needs —
  a zero-cell matrix concludes `skipped`, not `success`. Noted the vestigial
  `platform`/`ci:full-os`/`affected` machinery the same gated patch removes.
