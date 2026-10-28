# Changelog fragments

Pull requests add one fragment file here instead of editing `CHANGELOG.md`.
Queued pull requests that all edit `CHANGELOG.md` conflict with each other in
the merge queue; separate files do not.

## Format

- One file per pull request, named `<pr-number-or-slug>.md`, for example
  `512.md` or `proxy-partial-echo.md`. Lowercase letters, digits, `.`, `_`
  and `-` only.
- The file holds one or more sections. Each section is a level-3 heading
  that starts with `Added`, `Changed`, `Fixed`, `Security`, `Removed`,
  `Deprecated` or `CI`, optionally followed by a short topic in parentheses,
  then bullets. This matches the existing `CHANGELOG.md` style.

```markdown
### Fixed (`phantom wrap` keeps package.json formatting)

- `phantom wrap` and `phantom unwrap` no longer reformat package.json.
```

This README is never folded.

## Folding

`node scripts/changelog-fold.mjs` inserts every fragment, sorted by file
name, at the top of the `## [Unreleased]` section of `CHANGELOG.md`, then
deletes the fragment files. It refuses to run (and changes nothing) if a
fragment is malformed or `## [Unreleased]` is missing. Use `--check` to
validate fragments without writing anything.

The release workflow will run the fold at release time; until that wiring
lands, a maintainer runs it when cutting a release.
