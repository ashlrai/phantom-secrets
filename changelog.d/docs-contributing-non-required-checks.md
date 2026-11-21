### Changed (docs)

- CONTRIBUTING.md now says that the merge-queue `pair-secrets` test fails
  closed until its `ashlrai/phantom` side is wired in, and that only `CI Gate`
  blocks a merge: a red CodeQL, first-run scorecard, or `pair-secrets` check
  does not hold a pull request.
