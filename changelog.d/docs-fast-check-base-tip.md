### Changed (contributing: fast-check base)

- CONTRIBUTING.md now explains that one-argument `scripts/fast-check.sh BASE`
  compares with the tip of `BASE`, not the merge base, so a fresh
  `git fetch upstream` can widen the selection to the whole workspace, and
  says to rebase first or run `scripts/fast-check.sh upstream/main HEAD`.
