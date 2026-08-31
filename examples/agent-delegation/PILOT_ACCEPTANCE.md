# Phantom pilot acceptance record

This is a pilot template, not a certification or production authorization.

## Pilot identity

- Sponsor: `[role or team]`
- Security owner: `[role or team]`
- Engineering owner: `[role or team]`
- Repository and full starting SHA: `[identity]`
- Phantom version or source SHA: `[identity]`
- Workstation OS and architecture: `[identity]`
- AI client and version: `[identity]`
- Pilot start and expiry: `[dates]`

## Approved scope

- Managed dotenv files: `[paths]`
- Test credentials by name: `[ENV_VAR_NAME, ...]`
- Allowed provider test environments: `[none or exact targets]`
- Delegated tasks: `[bounded tasks]`
- Explicit exclusions: `[production, customer data, deployment, spend, ...]`

## Entry gates

- [ ] Credential recovery source exists outside the repository and agent.
- [ ] Task brief and repository agent policy are approved.
- [ ] Incident and rollback owners are named.
- [ ] Provider and deployment operations are denied unless separately approved.
- [ ] Data classification permits the named repository and test fixtures.

## Measured outcomes

| Measure | Target | Observed | Evidence |
|---|---|---|---|
| Setup time | `[target]` | `[result]` | `[record]` |
| Critical readiness findings at task start | `0` | `[result]` | `[report]` |
| Real credential values in agent-visible surfaces | `0` | `[result]` | `[review]` |
| Unprotected-secret check | `pass` | `[result]` | `[command output]` |
| Required focused tests | `pass` | `[result]` | `[command output]` |
| Unauthorized external mutations | `0` | `[result]` | `[audit/reconciliation]` |
| Reviewer acceptance | `pass` | `[result]` | `[review record]` |

## Evidence boundaries

- Source and local tests: `[observed or not performed]`
- Exact installed/built artifact: `[observed or not performed]`
- Cloud/team service: `[observed or not enabled]`
- Provider operation: `[observed or not authorized]`
- Deployment: `[observed or not authorized]`
- Customer workflow: `[observed or not performed]`
- Regulatory or contractual review: `[owner and status]`

## Incidents and recovery

`[Describe incidents without credential values, or state none observed.]`

## Decision

- [ ] Stop and remediate.
- [ ] Continue local open-source use on the named scope.
- [ ] Expand to another bounded pilot.
- [ ] Begin hosted/team and contractual diligence with Ashlr AI.
- [ ] Request missing product controls as planned work.

Decision owner, date, rationale, and next review:

`[record]`
