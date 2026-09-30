# Examples

Phantom examples are deliberately value-free. Never copy real credentials,
live provider identifiers, cloud tokens, device codes, cookies, or persistent
`phm_` mappings into an example or issue.

## Available examples

| Example | Status | Purpose |
|---|---|---|
| [First five minutes](first-five-minutes/README.md) | Executable, hermetic contract | Run a deterministic value-free delegation walkthrough with no network access, mutation, or persisted token mapping. |
| [Installed-runtime onboarding](agent-first-five-minutes/README.md) | Executable CLI/MCP smoke | Check both reviewed local binaries in disposable empty directories; no vault, credentials, or provider calls. |
| [Agent delegation templates](agent-delegation/README.md) | Documentation templates | Copyable policy, task brief, and pilot-acceptance structures for a bounded agent task. |
| [Claude Code](claude-code/README.md) | Executable recipe, disposable workspace | `init` → `setup --client claude` → MCP secret listing by name → `exec` with a placeholder and a local proxy URL → commit through the pre-commit hook. |
| [Cursor](cursor/README.md) | Executable recipe, disposable workspace and HOME | Merge Phantom into `~/.cursor/mcp.json` without touching existing servers, then query the configured server over MCP. |
| [GitHub Actions secret gate](github-actions/README.md) | Copyable workflow plus an executable local replay | A pull-request check that fails on raw dotenv values and hardcoded provider keys, with no vault or secrets in CI. |

The repository does not currently claim a stable Rust library API or ship a
live provider-enrollment example. Provider protocol engines and test-only mocks
are internal scaffolding; they are not runnable acceptance examples.

The client and CI recipes use a fake, non-provider key and an explicit
encrypted-file vault inside a temporary HOME. Each prints `PASS` lines and
exits `0` (all passed), `1` (a check failed) or `2` (binary missing, so
incomplete). CI runs them against the workspace build with
`node --test scripts/examples-client-recipes.test.mjs`.

## Using an example

1. Read the linked README and its trust-boundary notes.
2. Copy only the files needed for your project.
3. Replace all placeholders with names and scopes, never credential values.
4. Add your repository's exact tests, allowed external systems, approvals, and
   rollback path.
5. Treat any new mutation, provider, publication, or deployment as a new scope
   requiring separate authorization.

For product setup, start with the [getting-started guide](../docs/getting-started.md).
For development examples and tests, see [CONTRIBUTING.md](../CONTRIBUTING.md).
