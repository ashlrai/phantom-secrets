### Changed (contributing: CodeQL pull request scope)

- `CONTRIBUTING.md` no longer says CodeQL scans every pull request. It now
  describes what `codeql.yml` does: docs-only pull requests skip analysis,
  other pull requests analyze only the changed languages (Rust only when a
  workflow file changes), and pushes to `main`, the weekly security-extended
  run, and manual dispatch scan all five languages. It also notes that
  neither CodeQL nor `pair-secrets` is a required check.
