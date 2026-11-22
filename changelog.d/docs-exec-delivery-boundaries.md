### Fixed (exec delivery guidance)

- Remove the headless provider-pull workflow and automatic Docker Compose
  forwarding claim from troubleshooting. Explain terminal consent, existing
  vault provisioning, explicit container environments, and loopback boundaries.
- Align README and machine-readable wrapping guidance with the shared CLI/MCP
  selection rules, shell-command refusals, and supported-route requirement.
- Explain why a generated `SESSION_SECRET` with `no_route` does not deliver
  the stored signing value to an application's environment.
- Add documentation regressions for CI consent, Compose boundaries, script
  wrapping, and generated-secret delivery.
