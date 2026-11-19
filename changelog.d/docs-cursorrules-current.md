### Fixed (agent rule files match the current CLI and MCP catalog)

- `.cursorrules` no longer tells agents to pass a secret value on the command
  line (`phantom add <name> <value>` is rejected), no longer claims a fixed
  9-tool MCP catalog or a `value` parameter on `phantom_add_secret`, and no
  longer recommends `npx phantom-secrets-mcp`. It now points to
  `phantom setup --client cursor`, the canonical `tools/list` catalog, and the
  `confirm` plus out-of-band `approval_token` gates.
- `.cursorrules` and `.github/copilot-instructions.md` link agents working on
  Phantom itself to `AGENTS.md`, `CLAUDE.md`, and the agent path in
  `CONTRIBUTING.md`.
