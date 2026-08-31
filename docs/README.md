# Phantom documentation

This is the canonical map for Phantom's repository documentation. Start with the shortest guide that matches your task, then use the security and architecture material when evaluating trust boundaries.

## Start here

| Goal | Guide |
|------|-------|
| Protect a project for the first time | [Getting started](getting-started.md) |
| Delegate one bounded task to an AI coding client | [Safe delegation quickstart](delegation-quickstart.md) |
| Plan a team or enterprise pilot | [Enterprise adoption](enterprise-adoption.md) |
| Diagnose an install, vault, proxy, or cloud problem | [Troubleshooting](troubleshooting.md) |
| Obtain and inspect provider credentials after human consent | [Provider grants](grants-spec.md) |
| Understand components, trust boundaries, and activation status | [Architecture](architecture.md) |
| Understand supported operating systems, architectures, and current validation | [Platform support](platform-support.md) |
| Prepare or audit a release candidate | [Release and readiness](release-readiness.md) |
| Assemble a security or third-party review | [Security and audit index](audit-index.md) |
| Report a vulnerability | [Security policy](../SECURITY.md) |
| Evaluate Phantom's security assumptions and known gaps | [Threat model](../THREAT_MODEL.md) |

## Agent and editor integrations

These guides cover installation, MCP setup, the value-blind tool model, and daily workflows:

- [Safe delegation quickstart](delegation-quickstart.md) for the common cross-client workflow
- [Claude Code](claude-code.md)
- [Codex](codex.md)
- [Cursor](cursor.md)
- [Windsurf](windsurf.md)
- [Copyable agent policy, task brief, and pilot templates](../examples/agent-delegation/README.md)

The small conversation facade and the advanced MCP compatibility catalog are separate contracts. `phantom_do` is proposal-only and does not execute an action. `phantom_setup_workspace` can propose, create a bearerless request, or report status; applying that request requires a separate attached trusted terminal. Advanced tools retain their own explicit confirmation and out-of-band approval gates.

Provider issuance is a separate trusted-terminal CLI contract. A **provider
grant** records credential and renewal state produced after human consent; an
**authority grant** is the inactive execution-kernel authority type. Provider
grants never confer Locus authority, broker leases, or execution permission,
and provider consent is not exposed as an MCP tool. The
[grant specification](grants-spec.md) records the design-era target. The root
[issuance contract](../ISSUANCE_CONTRACT.md) is the original design contract
and retains historical design-status language.

## Operations

- [Enterprise adoption and evidence](enterprise-adoption.md)
- [Cloud login](login.md)
- [Vercel and Railway sync](sync.md)
- [CI/CD integration](ci-cd.md)
- [Shell prompt integration](shell-prompt.md)

## Architecture and project development

- [Current-state architecture and trust boundaries](architecture.md)
- [Release and readiness guide](release-readiness.md)
- [Security and audit index](audit-index.md)
- [Platform support and native acceptance matrix](platform-support.md)
- [Design-era provider-grant lifecycle specification](grants-spec.md)
- [Original provider-issuance design contract](../ISSUANCE_CONTRACT.md)
- [Contributing guide](../CONTRIBUTING.md)
- [Changelog](../CHANGELOG.md)
- [Code of Conduct](../CODE_OF_CONDUCT.md)
- [MIT License](../LICENSE)

The authority, Locus-contract, broker, runtime, session, and evidence crates are
fail-closed foundations, not activated production authority or execution. The
[architecture](architecture.md) and [threat model](../THREAT_MODEL.md) record
the current activation boundary and non-mitigations. A source implementation
or passing test does not by itself prove packaged, installed, native, provider,
or production acceptance.

## Machine-readable and publishing surfaces

- [`llms.txt`](llms.txt) and [`llms-full.txt`](llms-full.txt) mirror public product guidance for language-model consumers.
- [`index.html`](index.html) and related assets are legacy static-site sources. The
  standalone `pricing.html` and `waitlist.html` files are legacy snapshots, not
  redirects or an independent product or entitlement contract. The active product
  surface is the Next.js `/pricing` route; the legacy pages are excluded from the
  static sitemap.
- [`blog-launch.md`](blog-launch.md), [`blog-devto.md`](blog-devto.md), and [`hn-submission.md`](hn-submission.md) are launch/publishing drafts, not normative technical specifications.

When behavior conflicts with prose, treat code, closed schemas, tests, and release automation as authoritative and open a documentation issue. Avoid copying capability counts or platform promises into new documents unless an automated check enforces them.
