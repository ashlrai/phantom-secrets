### Changed (docs: contributor path on the website)

- The website's `apps/web/public/llms.txt` and `llms-full.txt` now give the
  fork-to-merged-pull-request path from "Contribute with an agent" that the
  repository's own `llms.txt` files already carried, written for a fork
  (`upstream/main` as the base), so agents reading the site find the same
  gates as agents reading the repository.
- `docs/llms-full.txt` no longer says CI runs the Rust test suite before
  release without qualification: the daily full run and the tag release
  workflow run it, and pull request CI does not.
- `CONTRIBUTING.md` lists the path-filtered First-run scorecard among the
  non-required workflows that can run on pull request code.
