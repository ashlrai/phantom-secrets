### Changed (docs: web checks run locally)

- `apps/web/README.md` no longer says pull request CI runs the web lint, test,
  and build steps. The web job runs only in the daily full run, so the guide
  now lists the full local sequence (`npm ci`, `npm audit`, `npm run lint`,
  `npm test`, `npm run build`).
- `CONTRIBUTING.md` adds `npm run lint` to the web application checks and
  tells `apps/web` contributors in "Contribute with an agent" to run them
  before opening a pull request.
