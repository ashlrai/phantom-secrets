# Project governance

Phantom is a maintainer-led open-source project stewarded by Ashlr AI. This file
describes the repository decision process; it does not create a hosted-service
entitlement, support contract, or authority to publish a release.

Phantom Secrets is one of the open-source tools from [Ashlr](https://ashlr.ai)
that together aim to be an autonomous, code-first, agent-native software
factory: coding agents write, test, review, and ship the code, and the human
acts as a passive board member. The long-term goal is open-source recursive
self-improvement (RSI). The governance below applies equally to changes written
by people and by agents.

## Decision process

- Small, reversible fixes are decided through pull-request review and the
  required `CI Gate` check, whether a person or a coding agent wrote them.
- Changes to trust boundaries, public protocols, compatibility, dependencies,
  provider/network behavior, release automation, or agent authority should
  begin with an issue or discussion and an explicit threat/rollback analysis.
- Maintainers make the final security-disclosure, release, and repository
  administration decisions. Merges are made by maintainers or by the coding
  agents operating under [AGENTS.md](AGENTS.md), which allows them to merge a
  pull request that passes `CI Gate` through the merge queue. Consensus is preferred, but safety can require a
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
contact identified in [CITATION.cff](CITATION.cff) and the support routes.

[`.github/CODEOWNERS`](.github/CODEOWNERS) names the owner of CI workflows, the
vault, proxy, broker, authority, session, evidence, and workspace crates, the
MCP server registration file, the web API and auth code, and the core files
that make keyed or network requests. GitHub uses only the first `CODEOWNERS`
file it finds and checks `.github/` first, so the root
[`CODEOWNERS`](CODEOWNERS) (release and publish paths) is not the active
mapping. Whether a
code-owner review is required, and other branch-protection settings, are
external repository state and must not be inferred from this document.

| Role | Responsibilities |
|---|---|
| Contributor | Proposes focused changes, adds proportional tests, documents limits, and follows the Code of Conduct. |
| Coding agent | Writes most changes. Follows [AGENTS.md](AGENTS.md) and the same contribution, security, and verification rules as a person, and never needs a real secret value. |
| Reviewer | Checks correctness, security boundaries, compatibility, evidence, and maintainability. |
| Maintainer | Merges changes, coordinates disclosures, curates releases, and administers repository settings. |

There is no automatic path from contribution volume to maintainer access.
Repository or release authority is granted explicitly by existing maintainers
after sustained, security-conscious participation.

## Releases and commercial boundaries

The reusable release gates are documented in
[docs/release-readiness.md](docs/release-readiness.md). A release starts with
a pull request that changes `[workspace.package].version` in `Cargo.toml`,
reviewed and merged like any other change. When that commit is on `main` and
every required check on it is green,
[`auto-tag.yml`](.github/workflows/auto-tag.yml) creates the `v<version>` tag,
and the tag runs [`release.yml`](.github/workflows/release.yml). That
workflow builds and verifies the release, then waits at the `release`
environment before it creates the GitHub release. The workflow expects that
environment to require a human reviewer; whether it does is repository state,
like the code-owner review above. Package publication, Homebrew updates,
deployment, provider commissioning, and customer acceptance remain separate
decisions.

Local open-source governance does not set hosted plan availability, pricing,
support, or enterprise terms. Those require deployed-service evidence and, when
applicable, a separate written agreement.

## Participation and escalation

- Use [CONTRIBUTING.md](CONTRIBUTING.md) for development and review rules, and
  [Contribute with an agent](CONTRIBUTING.md#contribute-with-an-agent) for the
  shortest path from a fork to a merged pull request.
- Use [SUPPORT.md](SUPPORT.md) to choose a public or private support channel.
- Follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) in all project spaces.
- Report vulnerabilities through [SECURITY.md](SECURITY.md), never a public issue.

Governance changes use the normal pull-request process and should explain why
the change improves contributor clarity, project safety, or accountability.
