### Changed (changelog fragment rules)

- `changelog.d/README.md` now states that only files ending in lowercase
  `.md` are read, so a fragment saved as `512.txt` or `512.MD` is skipped
  without an error and never reaches `CHANGELOG.md`. It also states that a
  fragment name starts with a letter or digit and that a bullet needs a space
  after `-` or `*`. `scripts/changelog-fold.test.mjs` exercises each rule.
