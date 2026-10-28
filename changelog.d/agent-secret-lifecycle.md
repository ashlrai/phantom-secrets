### Added (value-free agent secret lifecycle)

- `phantom add NAME --generate` creates a local 256-bit random secret without
  entering or returning a value; MCP `phantom_add_secret` supports
  `generate: true` under the existing confirm-plus-approval gates. A pending
  `phantom request` is fulfilled with its reserved placeholder.
- `phantom request NAME --purpose TEXT [--route ROUTE]` reserves a value-free
  pending secret and stable placeholder; `phantom requests --json` lists
  `phantom.requests.v1` receipts without vault access.
- `phantom rotate NAME --generate` atomically replaces a local value in the
  encrypted file vault under trusted-terminal consent; trusted-terminal
  `phantom rotate --name NAME --rollback` restores the single retained
  predecessor. MCP `phantom_rotate` accepts `generate` plus `name` under the
  existing effects and approval gates.
- `phantom audit --json [--since UNIX_SECONDS]` streams the chained usage log
  as JSONL; records now carry value-free `actor`, `route`, `host`, and
  `outcome` metadata. `phantom exec`, the MCP server, credential vault
  operations, and proxy dispatch require usage records and refuse unknown
  `PHANTOM_ENGINE_ID` identifiers.
