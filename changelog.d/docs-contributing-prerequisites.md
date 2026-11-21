### Changed (contributor prerequisites name every tool the checks need)

- `CONTRIBUTING.md` said Node.js was needed only for npm wrapper and
  `apps/web` work. Every change needs Node.js for the pre-push changelog
  fragment check and the docs drift checks, and Perl for the local
  `Secret-shape scan` that `CI Gate` requires. `scripts/fast-check.sh` and the
  affected-package selectors need Bash and Python 3. "Development setup" and
  step 2 of "Contribute with an agent" now list these tools.
