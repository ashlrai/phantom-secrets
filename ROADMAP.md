# Roadmap

This roadmap describes ordered engineering gates, not delivery dates or shipped
capabilities. The immutable `v0.7.3` release is the reviewed public
distribution. The repository currently stages `0.7.4`; its source and workflow
definitions do not prove an artifact was built, published, deployed, enabled,
or accepted.

## Status vocabulary

| Status | Meaning |
|---|---|
| Released | Present in an immutable published release with the named evidence. |
| Staged | Implemented in repository source and still awaiting release evidence. |
| Gated | Intended direction with explicit prerequisites; not available. |
| Exploratory | Research or design work with no compatibility or delivery commitment. |

## Current milestones

### 1. Close the 0.7.4 source candidate — staged

- Keep local mutations transactional and authority-sensitive operations
  fail-closed.
- Preserve the default-denied provider-issuance boundary.
- Keep public documentation, CLI help, and the generated 54-tool MCP registry
  aligned with runtime behavior.
- Pass locked workspace, dependency-policy, installer, wrapper, web, security,
  and schema gates on one exact clean SHA.

Completion at this layer establishes a source candidate only.

### 2. Produce and accept exact native artifacts — gated

- Run the tag-bound six-target release workflow.
- Verify each closed archive, checksum, SBOM, provenance binding, binary
  version, and MCP schema on its matching native runner.
- Record skipped or externally unavailable checks and keep notarization,
  Authenticode, and independent signing claims separate.

No platform archive is considered accepted solely because a workflow matrix or
cross-compile target exists in source.

### 3. Reconcile distribution tracks — gated

- Publish crates.io, npm, MCP Registry, Homebrew, and GitHub release surfaces
  only through their separately approved workflows.
- Verify exact version and byte identity for each immutable publication.
- Keep older tracks visibly distinct until their own publication receipts exist.

Publication on one channel does not authorize or prove another.

### 4. Expand network architecture only behind evidence — exploratory

The [Rama-derived design standard](docs/rama-design-standard.md) is an
architectural benchmark, not a runtime dependency. Typed service extraction,
transport fault tests, and a non-default spike must preserve Phantom's closed
route and credential-placement authority before any dependency decision.

### 5. Re-enable provider lifecycle paths only with recovery — gated

Live provider enrollment, issuance, refresh, renewal, rotation, and revocation
remain hard-denied. Re-enabling one provider requires a provider-specific,
durable recovery handle, verified compensation/abort behavior, exact terminal
authority, hermetic tests, and separately authorized provider acceptance.

### 6. Evaluate hosted and enterprise pilots separately — gated

Cloud, team, billing, key portability, centralized policy, SSO/SCIM, support,
and enterprise packaging require deployed-service configuration, migrations,
provider setup, rollback, written scope, and authenticated acceptance. Source
availability or local tests do not commission those capabilities.

## Non-goals

- General-purpose MITM or system-proxy behavior.
- Ambient agent authority to reveal, rotate, deploy, publish, or spend.
- Security, compliance, platform, or support guarantees inferred from source.
- Dates or adoption claims that lack an accountable owner and acceptance evidence.

Historical planning documents such as [PLAN.md](PLAN.md) record earlier design
thinking and are not the current roadmap. Current behavior is defined by code,
closed schemas, tests, the [changelog](CHANGELOG.md), and canonical documentation.
