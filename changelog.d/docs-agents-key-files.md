### Changed (docs: agent key files)

- The Key files list in AGENTS.md now matches the source: command routing is
  in `crates/phantom-cli/src/dispatch.rs`, not `main.rs`, and the list adds the
  files the repository conventions name (the CLI inventory guards in `util.rs`,
  the symlink-safe dotenv reader, the importer dispatcher, the audit log, the
  proxy service routes, response scrubber, and mock test server, and the MCP
  parameter and error helpers) plus every `apps/web` API route group.
