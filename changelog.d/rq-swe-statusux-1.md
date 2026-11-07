### Fixed (`phantom audit verify` failure guidance)

- `phantom audit verify` now prints actionable next steps when chain
  verification fails — treating the log as unreliable for the flagged
  period, checking `phantom audit incidents` and `phantom leaks plan`, and
  revoking and replacing affected credentials at their providers when
  tampering is suspected — in both the default and `--with-context` output.
- `phantom audit verify --json` reports the same guidance in a `next_step`
  field (`null` when the chain verifies clean).
