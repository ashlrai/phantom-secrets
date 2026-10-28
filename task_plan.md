# RQ-PS-AGENT-AUDIT
- [x] Inspect signed audit pipeline and operation hooks.
- [x] Add value-blind usage metadata and engine admission.
- [x] Add JSON query and regression coverage.
- [ ] Run targeted tests, check and lint; write bridge notes.

## Corrections during validation
- Generated test initially used rand 0.9 API; corrected to the locked rand 0.8 API.
- Clap subcommand conflict was incorrectly declared as an argument conflict; replaced with explicit usage validation.
- Initial test-file creation needed the new vault integration-test directory; created it.
- The exhaustive JSON command-classification test required an explicit `audit` entry for the new default query; updated its expected supported surface.
- Initial CLI rotation test filter selected zero tests; corrected to `commands::rotate` (the module uses `token_remap_tests`).
