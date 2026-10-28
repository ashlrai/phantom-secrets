### Fixed (doctor names the managed dotenv file)

- `phantom doctor` and the MCP `phantom_doctor` tool now name the dotenv file
  the project manages in their dotenv lines, for example
  `.env.local has 2 unprotected secret(s)` or `No .env.local file in current directory`.
  Before, these lines always said `.env`, even when `.phantom.toml` manages
  another file such as one chosen with `phantom init --from`. Only the
  message text changes. Which file doctor checks, the issue counts and the
  exit codes stay the same.
