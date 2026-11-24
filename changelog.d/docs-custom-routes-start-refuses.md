### Fixed (docs no longer say `phantom start` serves custom routes)

- `README.md`, `docs/agents.md`, `docs/troubleshooting.md`, `docs/litellm.md`
  and `docs/phantom-with-agents.md` said `phantom start` serves a custom route
  from `.phantom.toml`. It does not: `start` runs the same launch check as
  `phantom exec` (`validate_routes_for_launch`) before vault access, so both
  run only Phantom's exact built-in routes. The docs now say so, name
  `phantom doctor` as the way to find the blocking service, and point to
  `SECURITY.md` for why custom route approval is not supported yet.
