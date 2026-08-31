# Agent delegation templates

These templates turn Phantom's secret boundary into a reviewable task contract.
Copy and adapt them; do not use the examples as standing permission.

| Template | Use |
|---|---|
| [Agent policy](AGENT_POLICY.md) | Durable repository rules for any AI coding client. |
| [Task brief](TASK_BRIEF.md) | Scope, approvals, tests, and evidence for one delegated task. |
| [Pilot acceptance](PILOT_ACCEPTANCE.md) | Entry and exit gates for a team or enterprise pilot. |

Common instruction targets include `AGENTS.md`, `CLAUDE.md`,
`.github/copilot-instructions.md`, and a client's repository rule surface.
Preserve existing project instructions and merge only the relevant sections.
Client conventions can change; use the current client documentation to choose
the exact target.

Before copying a template:

1. remove placeholder text;
2. name secret variables only, never values;
3. identify every allowed external system and mutation;
4. add the repository's real test commands; and
5. require a new approval if scope changes.

Start with the [safe delegation quickstart](../../docs/delegation-quickstart.md).
For a team rollout, use the
[enterprise adoption guide](../../docs/enterprise-adoption.md).
