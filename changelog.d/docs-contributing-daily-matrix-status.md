### Changed (docs)

- `CONTRIBUTING.md` no longer says the daily full run has an off-peak,
  affected-only slot. `scripts/ci/daily-matrix.mjs` is described as a proposed
  refinement that no workflow calls yet: `nightly-full.yml` has one daily
  schedule and always runs the full matrix. The per-surface checks now sit
  under their own `Additional checks by surface` heading instead of under
  `Keyring advisory exceptions`, which moves to the end of `Verification`.
