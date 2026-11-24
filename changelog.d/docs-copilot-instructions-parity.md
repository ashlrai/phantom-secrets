### Changed (Copilot instructions match the Cursor rules)

- `.github/copilot-instructions.md` now carries the same safety rules as
  `.cursorrules`: never put a secret value in a command line, never ask for
  one in chat, and use `phantom why <KEY>` for a value-free check. A new MCP
  section says `phantom setup` has no Copilot client (print a snippet with
  `phantom setup --client claude --print`), that MCP never accepts or returns
  values, and that mutating tools need `confirm: true`, a one-use
  `approval_token`, and `PHANTOM_MCP_EFFECTS=trusted-terminal`.
