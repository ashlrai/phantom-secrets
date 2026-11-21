### Changed (contributor docs list every daily-only CI job)

- CONTRIBUTING.md now names the Windows ARM64 source check and the Temporal codec example tests among the jobs that run only in the daily full run, matching `ci.yml`.
- CONTRIBUTING.md gives the local command for the Temporal codec example tests, which pull request and merge-queue CI never run, so a change to `examples/temporal-codec-python/` has a documented check before it merges.
