### Fixed (README describes what pull request CI actually runs)

- The README's "How agents work on this repo" no longer says CI runs the docs
  drift checks on a change. Pull request and merge-queue CI (`CI Gate`) runs
  format, Clippy, dependency policy, and secret scans; `ci.yml` skips the
  Rust tests and the docs command check for `pull_request` and `merge_group`,
  so contributors run them and the other drift checks locally.
- The README "Contributing" section now links the "Contribute with an agent"
  path in `CONTRIBUTING.md` and lists the same four documentation drift checks
  as `AGENTS.md`, which also notes that pull request CI does not run them.
