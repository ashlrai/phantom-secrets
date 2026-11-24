### Changed (docs: contributor path on the website pages)

- The website's `/docs` hub ("Adopt and contribute") and the landing page's
  Ashlr ecosystem section now link "Contribute with an agent" in
  `CONTRIBUTING.md`, the fork-to-merged-pull-request path, and the ecosystem
  section states that `CI Gate` is the only required check and that fork
  contributors need no write access or repository secrets. A new
  `apps/web/tests/contributor-path.test.cjs` keeps the links and the anchor
  in sync.
- The README's "How agents work on this repo" no longer says pull request CI
  runs only format, Clippy, dependency policy, and secret scans: it also runs
  the npm wrapper tests when a change touches paths outside docs and the web
  app, as `.github/workflows/ci.yml` and `CONTRIBUTING.md` describe.
