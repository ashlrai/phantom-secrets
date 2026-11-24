### Changed (docs)

- The example `phantom status --json` documents in
  `docs/status-consumer-q8.md` now include the `schemaVersion` field, so they
  match the CLI test fixtures they claim to mirror. The guide also explains
  that `schemaVersion` and `schema_version` carry the same number, and lists
  the `available` and `held` lifecycle-lock states alongside the others.
