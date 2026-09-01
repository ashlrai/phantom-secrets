# Project governance

Phantom is a maintainer-led open-source project stewarded by Ashlr AI. This file
describes the repository decision process; it does not create a hosted-service
entitlement, support contract, or authority to publish a release.

## Decision process

- Small, reversible fixes are decided through pull-request review.
- Changes to trust boundaries, public protocols, compatibility, dependencies,
  provider/network behavior, release automation, or agent authority should
  begin with an issue or discussion and an explicit threat/rollback analysis.
- Maintainers make the final merge, security-disclosure, release, and repository
  administration decisions. Consensus is preferred, but safety can require a
  fail-closed decision or a delayed feature.
- Important decisions should be recorded in code, tests, canonical
  documentation, or a focused design record rather than relying on chat history.

Review favors the smallest design that preserves value blindness, explicit
authority, bounded resources, recoverability, and claim truth. A proposal,
passing source test, configured workflow, built artifact, publication,
deployment, provider activation, and user acceptance are separate evidence
layers.

## Roles

The current repository steward is Ashlr AI. Mason Wyatt is the public project
contact identified in [CITATION.cff](CITATION.cff) and the support routes. The
repository does not yet publish a verified GitHub `CODEOWNERS` mapping; review
assignment and branch-protection settings are external repository state and
must not be inferred from this document.

| Role | Responsibilities |
|---|---|
| Contributor | Proposes focused changes, adds proportional tests, documents limits, and follows the Code of Conduct. |
| Reviewer | Checks correctness, security boundaries, compatibility, evidence, and maintainability. |
| Maintainer | Merges changes, coordinates disclosures, curates releases, and administers repository settings. |

There is no automatic path from contribution volume to maintainer access.
Repository or release authority is granted explicitly by existing maintainers
after sustained, security-conscious participation.

## Releases and commercial boundaries

The reusable release gates are documented in
[docs/release-readiness.md](docs/release-readiness.md). A release requires a
separate maintainer decision on an exact clean SHA and tag; package publication,
Homebrew updates, deployment, provider commissioning, and customer acceptance
remain separate decisions.

Local open-source governance does not set hosted plan availability, pricing,
support, or enterprise terms. Those require deployed-service evidence and, when
applicable, a separate written agreement.

## Participation and escalation

- Use [CONTRIBUTING.md](CONTRIBUTING.md) for development and review rules.
- Use [SUPPORT.md](SUPPORT.md) to choose a public or private support channel.
- Follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) in all project spaces.
- Report vulnerabilities through [SECURITY.md](SECURITY.md), never a public issue.

Governance changes use the normal pull-request process and should explain why
the change improves contributor clarity, project safety, or accountability.
