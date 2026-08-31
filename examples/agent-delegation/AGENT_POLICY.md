# Repository AI delegation policy

## Secret handling

- This repository uses Phantom. Managed dotenv files contain `phm_`
  placeholders; do not treat them as broken credentials.
- Never request, reveal, print, log, copy, or write a real credential.
- Refer to credentials by environment-variable name only.
- Use Phantom MCP tools for value-blind inventory and status.
- If a credential is missing, request the interactive add flow. The human enters
  the value only in the trusted terminal prompt.
- Do not weaken dotenv deny rules, secret scanning, proxy authentication,
  service routing, or pre-commit checks to make a test pass.

## Before work

1. Confirm the repository, branch, task scope, and allowed external systems.
2. Run or request `phantom agent doctor` and stop on critical findings.
3. Inspect existing patterns before changing files.
4. Identify every operation that can mutate local, provider, cloud, deployment,
   billing, permission, or customer state.

## Approval boundary

Read-only inspection and local tests are allowed only within the task brief.
Obtain fresh human approval for the exact target before any:

- secret removal, rotation, copy, cloud/team write, or deployment sync;
- provider consent, issuance, revocation, or live validation;
- workspace apply, deployment, publication, permission change, or spend;
- destructive, irreversible, or customer-visible operation.

An approved task, plan, preview, or `confirm: true` parameter is not standing
authority for a different action. When approval is absent, stop at a value-free
proposal.

## Hard denials

- Do not paste credentials into chat, source, argv, logs, or test fixtures.
- Do not call reveal and capture its output.
- Do not bypass Phantom with a direct real-key environment variable.
- Do not claim Locus authority, broker leases, production execution, or trusted
  external receipts from the inactive foundation crates.
- Do not describe source, tests, or a readiness status as deployment, provider
  activation, regulatory compliance, or customer acceptance.

## Completion evidence

Report:

- exact files changed;
- tests and checks run with pass/fail/skip status;
- `phantom check`, `git diff --check`, and final `git status --short` results;
- external mutations separately, including approval and reconciliation; and
- remaining risks, blockers, and rollback information.
