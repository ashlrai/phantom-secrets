### Changed (pull request template and README list the pre-push checks)

- The pull request template's "How to verify" section and the README's
  Contributing section now include the two pre-push checks from
  `CONTRIBUTING.md`: `node scripts/changelog-fold.mjs --check` and the local
  form of the required `Secret-shape scan`. Before, the template a contributor
  fills in offered only the test and docs-drift command blocks.
