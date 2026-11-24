### Changed (docs: CI coverage claims)

- README, `docs/litellm.md`, `docs/phantom-with-agents.md`, `examples/README.md`, and the Temporal codec example README no longer say CI runs the Rust tests, the LiteLLM proxy tests, the example recipes, or the Temporal codec tests on every change or every push to `main`. Those run only in the daily full CI run and on manual dispatch; pull requests and the merge queue run only the fast checks.
- README now lists every file `docs_command_flags_test` reads, and CONTRIBUTING tells `apps/web` contributors to run it when they change a documented `phantom` command.
