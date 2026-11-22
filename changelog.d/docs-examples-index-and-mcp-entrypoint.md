### Changed (docs: examples index and MCP entrypoint)

- `examples/README.md` lists the PostHog capture script and the Temporal
  payload codec sketch, and says which recipes the daily CI run executes:
  Claude Code, Cursor, and GitHub Actions. The Next.js recipe runs only
  locally.
- `INTEGRATION.md` names the bundled MCP entrypoint as `phantom mcp serve`,
  the command `phantom setup` writes; bare `phantom mcp` needs a subcommand.
