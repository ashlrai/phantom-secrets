# Adopt Phantom with explicit enterprise gates

This guide helps security, platform, and engineering leaders evaluate Phantom
without converting source-level capabilities into production claims. It starts
with a bounded local pilot and produces evidence that can support a wider
adoption decision.

Phantom is MIT-licensed and local-first. An organization can evaluate and use
the open-source CLI, vault, proxy, and MCP server without a commercial contract.
Optional hosted, team, procurement, support, or contractual requirements are a
separate conversation with Ashlr AI and depend on the service, plan, written
terms, and environment actually approved. This repository does not claim an
enterprise certification, contractual SLA, or completed customer rollout.

## Know which layer you are evaluating

| Layer | Current repository boundary | What still needs separate evidence |
|---|---|---|
| Local secret protection | CLI initialization, vault backends, `phm_` placeholders, checks, and authenticated loopback proxy are shipped product paths. | Exact installed artifact, native environment, and organization-specific acceptance. |
| Agent integration | Setup writers exist for Claude Code, Codex, Cursor, and Windsurf; MCP returns value-blind metadata and separately gated operations. | Client policy, extension/version behavior, user acceptance, and task-specific authorization. |
| Cloud and teams | Client and web source implement encrypted cloud and team workflows. | Deployed-service state, plan entitlement, identity configuration, tenant acceptance, recovery, and contract terms. |
| Audit and posture | Local audit commands, readiness reports, and an MCP compliance-status badge are implemented. | Central collection, retention, reviewer independence, regulatory mapping, and an actual audit. |
| Provider-grant foundations | Value-free lifecycle metadata and protocol/design source remain available; 0.7.4 hard-denies every live provider path before credential or network access. | Durable successor recovery/verified abort, approved provider applications and scopes, live consent, renewal/revocation operations, and customer acceptance. |
| Governed execution | Workspace setup can be proposed by MCP and applied through a separate trusted-terminal transaction on Unix. | Production execution authority; Locus, broker, runtime, session, and externally trusted receipt foundations remain inactive. |

The MCP `phantom_compliance_status` result is a local five-check posture badge:
vault access, audit mode, a Phantom pre-commit hook, a clean managed `.env`, and
rotation-policy metadata. Its `compliant: true` field is not SOC 2, ISO 27001,
PCI DSS, HIPAA, or any other certification. Similarly, the CLI
`compliance-ready` status means its local readiness predicates passed; it does
not certify the organization.

## Expansion blockers to resolve explicitly

Do not treat the following as available enterprise controls:

- SSO/SAML and SCIM provisioning are planned rather than shipped;
- team member revocation currently fails closed because atomic membership
  removal and vault-key rotation are unavailable, so use fixed-membership test
  teams and do not make team vaults an offboarding control;
- audit policy and retention are not centrally enforced by the local CLI;
- headless Phantom Cloud pull in CI is unsupported;
- cloud-signed audit delivery is protocol-only and hard-disabled: setup refuses
  it before mutation, legacy settings fall back to encrypted local retention
  without network I/O, and no central ingest or reviewer workflow is
  commissioned; and
- the repository provides no regulatory certification or contractual SLA.

An organization that requires any blocker above should keep the pilot local or
record the missing control as planned work. Do not compensate with an ambient
credential, undocumented endpoint, manual database edit, or a promise in the
pilot report.

## Phase 0: approve a bounded pilot

Choose one non-production repository and one reversible task. Do not begin with
release credentials, production databases, payment movement, infrastructure
administration, customer data, or an autonomous deployment.

Complete the [pilot acceptance template](../examples/agent-delegation/PILOT_ACCEPTANCE.md)
before initialization. Name:

- the repository and owners;
- the supported workstation and AI client;
- the exact dotenv files in scope;
- allowed provider endpoints and test accounts;
- actions the agent may perform;
- actions requiring human approval;
- forbidden actions;
- rollback and incident owners; and
- measurable acceptance criteria.

Recommended first-pilot outcomes are setup time, critical readiness findings,
unprotected-secret detection, credential-value exposure incidents, focused test
completion, and reviewer acceptance. Do not substitute modeled savings or a
demo for measured pilot evidence.

## Phase 1: establish the local boundary

Each pilot participant follows the
[safe delegation quickstart](delegation-quickstart.md). Capture:

```bash
git rev-parse HEAD
git status --short
phantom agent report --json
phantom check
```

Store reports according to organizational policy. Readiness output is designed
to omit secret values, but filenames, secret names, provider names, and audit
metadata can still be sensitive operational information.

Acceptance gate:

- no real credential appears in the repository, task brief, agent transcript,
  generated file, or retained test log;
- critical readiness findings are resolved;
- the agent uses secret names and value-blind metadata only;
- required tests pass without bypassing the proxy boundary; and
- the reviewer can distinguish local source/test evidence from live operations.

## Phase 2: standardize client recipes and task contracts

Adopt one canonical policy based on the
[agent policy template](../examples/agent-delegation/AGENT_POLICY.md) and one
task brief per delegation. Keep client-specific setup in the existing guides:

- [Claude Code](claude-code.md)
- [Codex](codex.md)
- [Cursor](cursor.md)
- [Windsurf](windsurf.md)

For Copilot, use repository instructions and the supported VS Code MCP
configuration. Phantom does not currently ship a Copilot setup writer.

Require a fresh approval for every cloud/team write, deployment-platform sync,
credential rotation, secret removal, provider consent flow, workspace apply,
or other consequential mutation. Approval for a proposal or task does not
authorize every command the task might discover.

## Phase 3: add repository and CI enforcement

Use the repository pre-commit check as fast local feedback and CI as the durable
control:

```bash
phantom check --staged
```

The [CI/CD guide](ci-cd.md) documents the supported pattern. Headless Phantom
Cloud pull is not currently supported; do not invent an undocumented CI token
flow. Deployment-platform sync is a separate authorized operation, not an
automatic consequence of a passing local check.

For each repository, define owners for:

- Phantom configuration and approved service mappings;
- ignored findings and expiry dates;
- client instruction files;
- audit-log retention and access;
- provider rotation and recovery; and
- release or deployment approval.

## Phase 4: evaluate optional team and cloud workflows

Cloud and team operations change remote state. Verify plan entitlement,
organization identity, target team, membership, recovery, and data-handling
requirements before enabling them. Use test vaults first.

Do not infer deployed-service security from the repository alone. Require the
named environment's authentication, authorization, encryption, backup,
incident, and tenant-isolation evidence. Record cloud/team source review,
service deployment, configuration, and user acceptance as separate gates.

## Phase 5: assemble an evidence packet

Use the [security and audit index](audit-index.md) rather than copying security
claims into a static questionnaire. A pilot evidence packet should include:

1. repository, branch, full source SHA, installed Phantom version, platform,
   and AI client;
2. pilot scope, owners, approvals, and exclusions;
3. readiness and secret-check outputs with sensitive metadata handled under
   policy;
4. test commands, results, ignored checks, and failures;
5. audit-chain verification when audit mode is enabled;
6. incidents and recovery evidence;
7. deployment, provider, and customer acceptance as separate sections; and
8. the next decision, owner, and expiry date.

Local HMAC audit-chain verification detects changes relative to its local key
and chain. It does not resist a fully compromised same-user account, create an
external timestamp, or provide an independently signed execution receipt.

## Enterprise decision record

At the end of the pilot, choose one explicit state:

- **Stop:** acceptance criteria failed or the risk owner rejects the boundary.
- **Extend locally:** continue open-source use on named repositories and
  clients, without hosted/team activation.
- **Expand the pilot:** add a bounded repository, client, or test provider with
  new acceptance criteria.
- **Evaluate hosted/team use:** begin service, plan, identity, recovery, and
  contractual diligence with Ashlr AI.
- **Request product work:** document a missing control as proposed work; do not
  describe it as shipped.

No state above activates Locus or production agent execution. The current
authority, Locus-contract, broker, runtime, session, and evidence crates remain
fail-closed foundations. See [architecture](architecture.md) and the
[threat model](../THREAT_MODEL.md) for their activation blockers.
