### Changed (contributing: fork setup)

- The "Contribute with an agent" path in `CONTRIBUTING.md` now shows the fork
  setup commands: clone your fork, add `ashlrai/phantom-secrets` as
  `upstream`, and branch from `upstream/main`. It explains that the local
  checks diff against `main`, so on a fork you pass `upstream/main` (for
  example `scripts/fast-check.sh upstream/main`) or keep `main` in sync.
  Development setup now points fork contributors at those steps.
