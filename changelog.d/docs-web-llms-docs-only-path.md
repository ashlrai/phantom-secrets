### Changed (docs)

- The site's `llms.txt` and `llms-full.txt` now give the documentation-only contributor path: skip `scripts/fast-check.sh` and run the four docs drift checks, which pull request CI skips. A new web test, `apps/web/tests/llms-contributor-path.test.cjs`, keeps both files naming the contributor path, the pre-push checks, and every drift check.
