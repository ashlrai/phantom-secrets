### CI (PR classification engine)

- Added `scripts/ci/pr-classify.mjs`: one tested engine computing every
  changed-file classification `ci.yml` and `codeql.yml` need — suite
  selection, the `platform` OS-matrix flag, and per-language CodeQL selection.
  It carries forward the unlanded parts of #547: the `full-ci` label alias for
  `ci:full-os`, Tier-1 `.github/CODEOWNERS` paths selecting the OS matrix, an
  unreadable diff failing closed to full coverage, and `.github/` or
  build/dependency-config changes scanning all five CodeQL languages. The
  workflow wiring is a G1-gated follow-up documented in
  `scripts/ci/pr-classify.md`.
- `scripts/fast-check.sh` now runs `scripts/ci/*.test.mjs`, giving the
  previously unwired `daily-matrix.test.mjs` suite an executed home.
