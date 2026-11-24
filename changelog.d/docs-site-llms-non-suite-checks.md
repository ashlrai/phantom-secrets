### Changed (site llms.txt contributor path)

- The site's `llms.txt` and `llms-full.txt` now name the two doc checks that
  the `*.test.*` suite search misses, `bash scripts/test-docs-agents.sh` and
  `node scripts/freshness/check.mjs`, like every repository entry point.
  `scripts/agent-entry-points-pre-push.test.mjs` now checks both site files
  for them.
