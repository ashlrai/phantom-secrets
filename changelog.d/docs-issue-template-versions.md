### Changed (documentation issue form no longer pins 0.7.x releases)

- The documentation report form's "Which layer" dropdown listed v0.7.5,
  npm 0.7.4, and 0.7.7 source, several releases behind. Its options are now
  version-free (GitHub release, Homebrew tap, npm package, current `main`) and
  ask the reporter to name the exact version or commit SHA.
- `scripts/issue-templates.test.mjs` fails if any issue-form dropdown option
  pins a release version again.
