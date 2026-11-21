# Changelog fragments

Pull requests add one fragment file here instead of editing `CHANGELOG.md`.
Queued pull requests that all edit `CHANGELOG.md` conflict with each other in
the merge queue; separate files do not.

## Format

- One file per pull request, named `<pr-number-or-slug>.md`, for example
  `512.md` or `proxy-partial-echo.md`. Lowercase letters, digits, `.`, `_`
  and `-` only, starting with a letter or digit.
- Only files ending in lowercase `.md` are read. A fragment saved as
  `512.txt` or `512.MD` is skipped without an error: the check still passes
  and the fold never adds it to `CHANGELOG.md`.
- The file holds one or more sections. Each section is a level-3 heading
  that starts with `Added`, `Changed`, `Fixed`, `Security`, `Removed`,
  `Deprecated` or `CI`, optionally followed by a short topic in parentheses,
  then bullets. This matches the existing `CHANGELOG.md` style.
- The first line must be one of those headings. Any other `###` heading, and
  any `#` or `##` heading, fails the check.
- The fragment needs at least one bullet line: `-` or `*` followed by a
  space. An empty fragment fails.

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
validate fragments without writing anything; run it before you push. On
success it prints `changelog-fold: N fragment(s) valid (check only)`; on
failure it exits 1 and names the file and the rule it broke, for example
`changelog-fold: 512.md: needs at least one bullet`.
`node --test scripts/changelog-fold.test.mjs` checks that this README states
the same rules the script enforces.
Pull request and merge-queue CI do not validate fragments. The daily full run
does (`Crate publication contract` in `ci.yml`), so a malformed fragment
otherwise merges and fails that run.

The release workflow will run the fold at release time; until that wiring
lands, a maintainer runs it when cutting a release.
