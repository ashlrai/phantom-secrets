### Added (workbench integration notes)

- `INTEGRATION.md` describes how this repo plugs into the Phantom workbench
  (formerly Ashlr Hub): opt-in delegation, the local proxy, trust boundaries,
  and opt-out. `DESIGN-onboarding-wizard.md` and `DESIGN-connector-packs.md`
  remain proposals and are not implemented.

### Fixed (npm install-source marker)

- The `phantom-secrets` and `phantom-secrets-mcp` wrappers write
  `.phantom-install-source.npm-cli` and `.phantom-install-source.npm-mcp` only
  after binary validation succeeds. A failed validation leaves no ownership
  marker.
