# AI delegation task brief

Replace every bracketed field before use.

## Identity

- Repository: `[absolute path or owner/repository]`
- Branch or worktree: `[name]`
- Starting source SHA: `[full SHA]`
- Requester: `[role or team, not a credential]`
- Reviewer: `[role or team]`
- Expiry: `[date or end-of-task condition]`

## Objective

`[One concrete outcome.]`

## In scope

- Files or modules: `[exact paths]`
- Secret names, values excluded: `[ENV_VAR_NAME, ...]`
- Read-only external systems: `[none or exact systems]`
- Allowed local mutations: `[exact changes]`

## Requires a fresh human approval

- `[Exact local or external mutation and target]`
- `[Provider, deployment, permission, billing, or customer-visible action]`

For each approval, record the approver, exact target, expected effect, recovery
method, and reconciliation check. Approval does not carry to a changed target.

## Forbidden

- Real credential disclosure or plaintext handling in agent context.
- `[Production, provider, deployment, publication, destructive, or spend action]`
- Scope expansion beyond the listed repository, files, or systems.
- Claims of deployment, activation, compliance, or acceptance without direct
  evidence for that layer.

## Required checks

```text
[repository-specific focused test]
phantom check
phantom agent doctor
git diff --check
git status --short
```

## Acceptance evidence

- Source/diff: `[required evidence]`
- Automated tests: `[required evidence]`
- Built artifact: `[not required or exact artifact evidence]`
- Deployment/provider: `[not authorized or exact receipt]`
- User/customer acceptance: `[not performed or exact workflow]`
- Skipped/blocked: `[list with owner]`

## Recovery

- Last known-good state: `[SHA, backup, or provider state]`
- Rollback owner: `[role or team]`
- Reconciliation command or procedure: `[exact safe check]`
