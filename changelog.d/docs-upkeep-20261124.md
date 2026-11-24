### Added (npm wrapper usage reporting)

- The npm wrapper now schedules an install report on first run and an active
  report after seven days since the last successful report
  ([#1586](https://github.com/ashlrai/phantom-secrets/pull/1586)). The payload
  includes tool/version, platform, CI/internal classification, and a random
  installation ID; it excludes secret values, placeholders, paths, project
  names, command arguments, and environment values. Disable reporting with
  `ASHLR_TELEMETRY=0`, `PHANTOM_TELEMETRY=0`, `DO_NOT_TRACK=1`, or
  `"disabled": true` in `~/.ashlr/usage-telemetry.json`. This reporting is in
  the npm wrapper source, not the native binary. Failed sends may retry after
  one hour.

### Changed (agent contributor entry points)

- `GEMINI.md` imports the canonical `AGENTS.md` instructions, and the pull
  request template includes an optional "Agent used" field
  ([#1587](https://github.com/ashlrai/phantom-secrets/pull/1587)).

### CI (first-run release checks)

- The first-run workflow pins its release to `v0.8.11` and adds a Windows
  x64 archive check that verifies the pinned checksum, the checksum sidecar,
  and both binary versions. Linux and macOS retain install-to-first-wrapped-exec
  timing; the Windows row checks installation and versions only
  ([#1602](https://github.com/ashlrai/phantom-secrets/pull/1602)).

### Fixed (secret-management documentation matches current behavior)

- Give team invitations and expiry enforcement their own command-reference
  rows so `--role` and `--fail-closed` attach to the commands that accept them.
- Document the MCP generated-secret operation, which returns a value-free
  receipt instead of accepting or returning plaintext secret values.
- Distinguish remapping persistent project placeholders from rotating provider
  credentials or invalidating an already running `phantom exec` session.
- Explain that status reports the machine-local lifecycle lock; a held lock
  does not establish listener health or authentication.
- Replace walkthrough commands that printed managed mappings or proxy bearers
  with value-free checks, and reject those values in the walkthrough test log.
- Correct the doctor output example: local diagnostics do not open the vault;
  an explicit `phantom agent doctor --json --vault` probes its inventory.
- Set the shell-test fixture's `NODE_ENV` explicitly so the existing quick-start
  staging tests pass the web application's strict typecheck.
- Refresh the platform quickstart reference to the displayed `v0.8.11`
  installer source commit, SHA-256 digests, and version-check label.
- Align platform acceptance rows and the CI public-installer assertion with
  the existing immutable `v0.8.11` receipt. Regression checks reject stale
  source commits, workflow links, or individual native rows.
- Preserve exact source package inventories after the npm reporting addition:
  seven CLI files and six MCP files. Document that the versioned candidate
  acceptance gate still needs separate reconciliation before publication.
