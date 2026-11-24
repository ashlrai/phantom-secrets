### Changed (docs: reproduce the required pull request jobs locally)

- `CONTRIBUTING.md` gains "Reproduce the pull request jobs locally", a table
  that maps each job `CI Gate` requires on a pull request (`Lint`, the npm
  wrapper tests, `Secret-shape scan`, `Rust dependency policy`, and
  `Source secret scan`) to the commands `.github/workflows/ci.yml` runs, and
  lists the docs and web paths that skip the Rust steps. Step 4 of
  "Contribute with an agent" links to it.
