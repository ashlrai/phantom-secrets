### Fixed (doctor names the managed dotenv file)

- `phantom doctor` and the MCP `phantom_doctor` tool now name the dotenv file
  the project manages in their dotenv lines, for example
  `.env.local has 2 unprotected secret(s)` or `No .env.local file in current directory`.
  Before, these lines always said `.env`, even when `.phantom.toml` manages
  another file such as one chosen with `phantom init --from`. Only the
  message text changes. Which file doctor checks, the issue counts and the
  exit codes stay the same.

### Security (dotenv file names with control characters are refused)

- A `phantom.dotenv_path`, or an `env_path` argument to the MCP
  `phantom_init` tool, that contains a control character such as a newline
  is now refused as an invalid file name. Such a name was echoed into doctor reports, results
  returned to MCP agents and, with `doctor --fix`, a `.gitignore` line, where
  it could forge extra lines.
