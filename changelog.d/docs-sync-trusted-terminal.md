### Changed (docs: live sync needs a trusted terminal)

- `docs/sync.md`, `docs/ci-cd.md`, and the GitHub Actions, Vercel, and Railway
  integration READMEs now say that a live `phantom sync` needs attached
  terminals and an exact typed `SYNC <plan-digest> <nonce>` challenge, and
  refuses to run headlessly before reading any vault value. The GitHub Actions
  README no longer lists a live sync as a CI option; only
  `phantom sync --dry-run --json` runs in CI.
- The Railway integration README gains a current CLI flow: `RAILWAY_TOKEN`,
  the default `production` environment at the project level, `[[sync]]`
  `service_id` and `environment_id`, and `phantom pull --from railway`.
