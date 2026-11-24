### Changed (docs)

- `GOVERNANCE.md` now describes the release path the workflows implement: a
  merged `Cargo.toml` version bump with green required checks is tagged by
  `auto-tag.yml`, and `release.yml` waits at the `release` environment before
  creating the GitHub release. It no longer says a release needs a separate
  maintainer decision on a SHA and tag.
