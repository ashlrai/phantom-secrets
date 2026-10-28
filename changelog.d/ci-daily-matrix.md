### CI (daily full-suite queue wait)

- Added `scripts/ci/daily-matrix.mjs` and `scripts/ci/offpeak-schedule.json`: the
  tool computes an affected-only OS matrix for the daily `Test (${{ matrix.os }})`
  job (per-leg `cfg` routing, failing closed to all three legs) and emits the
  additive off-peak cron `43 3 * * *`. Required check names are unchanged, and
  the suite asserts a projected wall time inside the 900-second budget.
