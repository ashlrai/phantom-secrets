# Examples

Phantom examples are deliberately value-free. Never copy real credentials,
live provider identifiers, cloud tokens, device codes, cookies, or persistent
`phm_` mappings into an example or issue.

## Available examples

| Example | Status | Purpose |
|---|---|---|
| [First five minutes](first-five-minutes/README.md) | Executable, hermetic contract | Run a deterministic value-free delegation walkthrough with no network access, mutation, or persisted token mapping. |
| [Agent delegation templates](agent-delegation/README.md) | Documentation templates | Copyable policy, task brief, and pilot-acceptance structures for a bounded agent task. |

The repository does not currently claim a stable Rust library API or ship a
live provider-enrollment example. Provider protocol engines and test-only mocks
are internal scaffolding; they are not runnable acceptance examples.

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
