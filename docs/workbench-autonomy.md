# Fleet and autonomy

Use **Work for me** to define a durable engineering outcome with acceptance criteria. The Leader refines priorities and tasks across enrolled repositories. An outcome's history links runs, proposals and verified merge evidence; it does not itself activate a fleet.

## Inspect current readiness

Use the installed workbench:

```sh
phm authority status --json
phm authority setup --dry-run --json
phm authority resident status --json
```

Inspect the grant, autonomy switch, Stop state, rollout stage, custody and resident service admission. In Resources, check qualified accounts, usage freshness, capacity and signed reserves. Connection is distinct from eligibility; missing usage must remain unknown.

Resident autonomy is macOS-only and ships dormant. Interactive work can be available while unattended work remains blocked.

## Complete operator commissioning

Follow the [canonical autonomy setup procedure](https://github.com/ashlrai/phantom/blob/37900cb15b0b07f4f6e81b2eb7f1e99d02d13c05/docs/AUTONOMY-SETUP.md) for the installed release. It prepares custody, a Secure Enclave key, compiled trust roots, the GitHub App, repository protections, canary and signed authority. Setup itself never installs or restarts the daemon.

The operator signs the standing grant through Touch ID and starts the resident service in their own trusted terminal. Agents must not execute or emulate these ceremonies. Missing custody, an expired grant, Stop, a disabled switch or a dirty build can hold resident work. Read the actual blocker before changing configuration.

Standing grants name repository, engine, account-role, risk, size and spend limits. The effective limits combine the grant, configuration and compiled policy. Renewing an existing grant does not silently widen scope. Lowering the switch, Stop and revocation remain available to the operator.

## Give the fleet a measurable outcome

1. Select Work for me and create an outcome.
2. Choose already enrolled repositories and add observable acceptance criteria.
3. Inspect the proposed task plan, resource eligibility and budget.
4. Review runs, proposals and Needs you as work progresses.
5. Verify matching merge and deployment evidence before declaring delivery.

Saving projects and changing workspaces does not enroll repositories. Editing an outcome does not widen a standing grant. Local models have hardware limits; provider accounts keep their own quotas and prices.

## Make improvements earn their place

Prefer a clear hypothesis and a reproducible comparison. Record the base and candidate source, test scope, execution time, failures, resource usage and the intended user benefit. A high-leverage proposal should still explain its blast radius, rollout and recovery path.

Track a PR's proposed benefit, verified checks, merge outcome and subsequent regressions. A judge recommendation or Jev scheduling decision is advice within the existing gates, not permission to merge or deploy. Inspect `phm jev status --json` for the local decision ledger; it is not proof of a currently authenticated provider or a retrospective PR score.

The published source includes proposal-oriented self-improvement. Do not describe every drafted improvement as accepted, merged, deployed or learned from production. Consult [improvement guidance](https://github.com/ashlrai/phantom/blob/37900cb15b0b07f4f6e81b2eb7f1e99d02d13c05/docs/IMPROVEMENT-BACKLOG.md) and [standing authority](https://github.com/ashlrai/phantom/blob/37900cb15b0b07f4f6e81b2eb7f1e99d02d13c05/docs/STANDING-AUTHORITY.md) for the current safeguards.

## Verify delivery

Separate local tests, a published package, an installed app, an admitted resident service, a head-bound verified merge and a production deployment. Record exact source identity and fresh readback at each applicable gate. A source guide cannot certify another user's live state.

For held work, follow [troubleshooting](workbench-troubleshooting.md). For commands, see [the reference](workbench-reference.md).
