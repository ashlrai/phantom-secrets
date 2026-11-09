### CI (PowerShell installer pin)

- The Windows CI job and the release rehearsal contract test now expect the
  public-reference `apps/web/public/install.ps1` to be pinned to the evidenced
  `v0.8.7` release instead of `v0.7.9`; the contract test reads the pin from
  the installer itself.

### Changed (repository docs tooling)

- A `.devin/wiki.json` steering file describes the workspace crates for
  generated repository wikis.

### Removed (unrouted `phantom env` help hint)

- The unused `run_default` helper in `env_scope.rs` is gone; `phantom env`
  still generates `.env.example` as documented.
