### Changed (changelog fragment rules match the validator)

- `changelog.d/README.md` now lists every rule `node scripts/changelog-fold.mjs --check` enforces (first line must be a section heading, no `#` or `##` headings, at least one bullet, no empty fragment) and shows the success and failure output.
- New `scripts/changelog-fold.test.mjs` runs the validator against throwaway roots to keep the README's section names, example, messages, and fold order in step with the script.
