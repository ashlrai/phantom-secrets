### CI (fork pull requests)

- A fork pull request no longer fails `CI Gate` when the read-only token cannot write the Actions cache. Tool archives are still verified and the checks still run; the save is skipped on `pull_request` and does not fail the job if a later save is denied.
- `Lint` does not upload the Rust cache on a pull request. `merge_group` and the nightly run still save it.
- Pull request classification no longer runs `cargo metadata` to build a nextest filterset the Test job does not use.

### Fixed (versioned JSON on Windows)

- `phantom --json env` and `phantom --json add --generate` no longer write the directory-durability warning to stderr, so a successful receipt stays machine-readable on Windows.
