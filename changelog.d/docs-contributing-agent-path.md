### Changed (CONTRIBUTING has an agent contributor path and accurate CI)

- `CONTRIBUTING.md` gains a "Contribute with an agent" path: fork, set up,
  `scripts/fast-check.sh`, the full local gate, a changelog fragment, and how
  `CI Gate`, the merge queue, and auto-merge finish the pull request.
- The Verification section now matches `ci.yml`: pull requests and the merge
  queue run only fast checks, and the full test matrix runs daily through
  `nightly-full.yml` rather than on pushes to `main`.
