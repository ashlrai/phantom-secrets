### Fixed (contributor guide matches the current release and local check scripts)

- `CONTRIBUTING.md` no longer pins the provider-grant hard-denial to 0.7.5;
  the repository map and grant note now describe current releases and point to
  the `grant` command source, matching the guide's own rule against volatile
  version claims.
- The "Testing affected Rust packages" section moved from under "Questions"
  into "Verification", where the agent path links to it, and now documents
  `scripts/fast-check.sh [BASE [HEAD]]` and exactly what it runs alongside
  `scripts/affected-tests` and `make test-affected`.
