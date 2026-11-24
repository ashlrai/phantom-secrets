### Changed (contributor docs match the npm wrapper and web CI jobs)

- CONTRIBUTING.md now runs each npm wrapper with `npm test` and `npm pack --dry-run`, the same steps as CI's npm wrapper job. The old per-file loop over `npm-mcp/test/` skipped the shared install-source-marker test and never packed the primary wrapper.
- CONTRIBUTING.md and `apps/web/README.md` list the credential-free steps of the daily web job, including the migration-contract and SEO-observation `node --test` suites, and say when the Supabase migration replay is needed.
