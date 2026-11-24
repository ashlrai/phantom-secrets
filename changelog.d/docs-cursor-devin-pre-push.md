### Changed (Cursor and Devin entry points list the pre-push checks)

- `.cursorrules` and the Devin wiki notes (`.devin/wiki.json`) now name the
  two pre-push checks (`node scripts/changelog-fold.mjs --check` and the local
  `Secret-shape scan`), tell fork contributors to diff against
  `upstream/main`, and point at "Contribute with an agent" in
  `CONTRIBUTING.md`. The earlier entry-point update missed both files.
- New `scripts/agent-entry-points-pre-push.test.mjs` checks that every agent
  entry point keeps naming both checks, `upstream/main`, and the contributor
  path.
