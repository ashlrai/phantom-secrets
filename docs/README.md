# Phantom documentation

This is the canonical map for Phantom's repository documentation. Start with the shortest guide that matches your task, then use the security and architecture material when evaluating trust boundaries.

Release-state snapshot verified on 2026-09-29: the immutable GitHub release
`v0.7.9` resolves to source commit
`7a51ce512ec4aee12cc29ff859036af63fbe93db`. Its exact 19-asset set, all six
native release rows, checksums, archive-specific SPDX SBOMs, and GitHub
provenance and SPDX attestations are bound to that immutable release by
[workflow 34153902556](https://github.com/ashlrai/phantom-secrets/actions/runs/34153902556).
See [distribution status](distribution-status.md) for dated npm, Homebrew, crates.io, and MCP Registry evidence. Prefer the checksum-verified `v0.7.9` GitHub assets for an exact install. The GitHub receipt alone does not establish hosted-service commissioning, provider activation, certification, or customer acceptance.

## Start here

| Goal | Guide |
|------|-------|
| Run GitHub PR operations through Phantom with curl | [GitHub box runners](github-box-runners.md) |
| Protect a project for the first time | [Getting started](getting-started.md) |
| Understand the landing-page install commands | [Quickstart reading guide](quickstart-reading-guide.md) |
| Locate and compare the landing-page command controls | [Quickstart command presentation](quickstart-command-presentation.md) |
| Follow the order of quickstart staging and cleanup | [Quickstart command sequence](quickstart-command-sequence.md) |
| Copy the landing-page install command safely | [Quickstart copy checklist](quickstart-copy-checklist.md) |
| Review platform labels, readability, and cleanup | [Quickstart reader checklist](quickstart-reader-checklist.md) |
| Review the clarity of landing-page installation copy | [Quickstart copy review](quickstart-copy-review.md) |
| Review platform-specific landing-page copy | [Quickstart platform copy review](quickstart-platform-copy-review.md) |
| Compare the landing-page install commands by platform | [Quickstart platform comparison](quickstart-platform-comparison.md) |
| Map displayed quickstart steps to their platform and source | [Quickstart platform step map](quickstart-platform-step-map.md) |
| Understand when quickstart commands use temporary directories | [Quickstart temporary directory usage](quickstart-temp-directory-usage.md) |
| Review temporary installer cleanup by platform | [Quickstart cleanup review](quickstart-temp-cleanup-review.md) |
| Find the displayed installer staging and cleanup steps | [Quickstart staging and cleanup](quickstart-stage-cleanup.md) |
| Locate and compare temporary directory snippets | [Quickstart staging snippet count](quickstart-stage-snippet-count.md) |
| Understand the Unix quickstart temporary directory fallback | [Quickstart temporary directory fallback](quickstart-temp-fallback.md) |
| Locate temporary installer files and their environment inputs | [Installer temporary locations](installer-temp-environment.md) |
| Review failure-reporting questions for Unix PATH setup | [Installer PATH update questions](installer-path-update-questions.md) |
| Find the Unix installer's staging parent and directory name | [Installer stage parent](installer-stage-parent.md) |
| Interpret the Unix installer staging prefix | [Installer staging prefix](installer-staging-prefix.md) |
| Identify the staging prefix and parent in each Unix installer copy | [Installer staging prefixes](installer-staging-prefixes.md) |
| Follow the public Unix installer staging and cleanup flow | [Public installer staging flow](public-installer-staging-flow.md) |
| Review cleanup questions for the public Unix installer | [Public installer staging questions](public-installer-staging-questions.md) |
| See a measured Linux install and the agent-CLI audit | [First run](FIRST-RUN.md) |
| Compare install, exec, and memory with dotenvx and SOPS | [Benchmarks](BENCHMARKS.md) |
| Delegate one bounded task to an AI coding client | [Safe delegation quickstart](delegation-quickstart.md) |
| Keep personal, company, and client keys separate | [Multi-project key separation](multi-project-keys.md) |
| Plan a team or enterprise pilot | [Enterprise adoption](enterprise-adoption.md) |
| Understand open-source rights and paid evaluation paths | [Commercial offerings](commercial-offerings.md) |
| Plan a public-sector evaluation | [Government evaluation](government-evaluation.md) |
| Review the shipped security boundary | [Security evaluation](security-evaluation.md) |
| Understand commercial support boundaries | [Commercial support](commercial-support.md) |
| Use the project name or logo accurately | [Project name and logo use](trademark-policy.md) |
| Diagnose an install, vault, proxy, or cloud problem | [Troubleshooting](troubleshooting.md) |
| Run LiteLLM as an optional gateway that never holds a real key (experimental) | [LiteLLM gateway](litellm.md) |
| Use Phantom with AI agents: exec, the proxy, LiteLLM, Temporal and post-quantum TLS, each claim tied to a test | [Phantom with agents](phantom-with-agents.md) |
| Understand the provider-grant design and 0.7.9 universal hard denial | [Provider grants](grants-spec.md) |
| Understand components, trust boundaries, and activation status | [Architecture](architecture.md) |
| Review the Rama-derived network engineering standard and adoption gates | [Rama design standard](rama-design-standard.md) |
| Understand supported operating systems, architectures, and current validation | [Platform support](platform-support.md) |
| Prepare or audit a release candidate | [Release and readiness](release-readiness.md) |
| Review the current unsigned boundary and future signing gates | [Signing and notarization readiness](signing-and-notarization.md) |
| Assemble a security or third-party review | [Security and audit index](audit-index.md) |
| Report a vulnerability | [Security policy](../SECURITY.md) |
| Evaluate Phantom's security assumptions and known gaps | [Threat model](../THREAT_MODEL.md) |
| Find contribution, support, or project-decision routes | [Community and project health](#community-and-project-health) |

## Agent and editor integrations

These guides cover installation, MCP setup, the value-blind tool model, and daily workflows:

- [Safe delegation quickstart](delegation-quickstart.md) for the common cross-client workflow
- [Hub status contract](hub-status-contract.md) for value-free local-orchestrator inspection (shipped in v0.7.9)
- [Generated secrets](generated-secrets.md) for value-free local secret creation via `phantom add --generate` and `phantom_add_secret` `generate: true`
- [Installed-runtime smoke](../examples/agent-first-five-minutes/README.md) for disposable CLI and MCP checks
- [Claude Code](claude-code.md)
- [Codex](codex.md)
- [Cursor](cursor.md)
- [Windsurf](windsurf.md)
- [Temporal workers with no secrets on disk](temporal.md) (optional guidance, untested design)
- [PostHog fleet capture](posthog.md) (header-only v1 event ingestion)
- [Copyable agent policy, task brief, and pilot templates](../examples/agent-delegation/README.md)
- [Examples index](../examples/README.md), including status and safety notes

The small conversation facade and the advanced MCP compatibility catalog are separate contracts. `phantom_do` is proposal-only and does not execute an action. `phantom_setup_workspace` can propose, create a bearerless request, or report status; applying that request requires a separate attached trusted terminal. Effectful advanced tools are disabled by default; `PHANTOM_MCP_EFFECTS=trusted-terminal` may enable their confirmation and one-use approval gates only when configured outside agent authority. Approval requires attached stdin/stderr, an informed value-blind summary, and a fresh typed challenge. A same-user shell or agent-controlled PTY can defeat the ceremony, so the approval command and storage must also be outside agent authority.

Provider issuance is not active in 0.7.9: every live enrollment exchange,
issuance, refresh, renewal, rotation, and revocation path is hard-denied before
provider credential or network access. A **provider grant** is design-era
lifecycle metadata; an **authority grant** is the inactive execution-kernel
authority type. Neither confers Locus authority, broker leases, or execution
permission. Exact `cfg(test)` mocks are local transaction evidence only. The
[grant specification](grants-spec.md) records the design-era target. The root
[issuance contract](../ISSUANCE_CONTRACT.md) is the original design contract
and retains historical design-status language.

## Operations

- [Enterprise adoption and evidence](enterprise-adoption.md)
- [Commercial offerings around the MIT core](commercial-offerings.md)
- [Commercial support boundary](commercial-support.md)
- [Government evaluation](government-evaluation.md)
- [Security evaluation](security-evaluation.md)
- [Cloud login](login.md)
- [Device authorization code format](device-code-format.md)
- [Readable device authorization code format](device-code-readable-format.md)
- [Device authorization input hint](device-code-input-hint.md)
- [Vercel and Railway sync](sync.md)
- [CI/CD integration](ci-cd.md)
- [Shell prompt integration](shell-prompt.md)
- [npm publication](npm-publication.md)
- [MCP Registry publication](mcp-registry-publication.md)

## Architecture and project development

- [Current-state architecture and trust boundaries](architecture.md)
- [Rama-derived network engineering standard](rama-design-standard.md)
- [Release and readiness guide](release-readiness.md)
- [Signing and notarization readiness](signing-and-notarization.md)
- [Security and audit index](audit-index.md)
- [Platform support and native acceptance matrix](platform-support.md)
- [Design-era provider-grant lifecycle specification](grants-spec.md)
- [Original provider-issuance design contract](../ISSUANCE_CONTRACT.md)
- [Contributing guide](../CONTRIBUTING.md)
- [Roadmap and milestone gates](../ROADMAP.md)
- [Project governance](../GOVERNANCE.md)
- [Changelog](../CHANGELOG.md)
- [Code of Conduct](../CODE_OF_CONDUCT.md)
- [MIT License](../LICENSE)

The authority, Locus-contract, broker, runtime, session, and evidence crates are
fail-closed foundations, not activated production authority or execution. The
[architecture](architecture.md) and [threat model](../THREAT_MODEL.md) record
the current activation boundary and non-mitigations. A source implementation
or passing test does not by itself prove packaged, installed, native, provider,
or production acceptance.

## Community and project health

- [Contributing](../CONTRIBUTING.md) — setup, repository map, security rules,
  test tiers, and pull-request expectations
- [Support](../SUPPORT.md) — discussions, public issues, private security
  reports, and commercial-evaluation routing
- [Governance](../GOVERNANCE.md) — maintainer-led decisions, roles, release
  authority, and commercial boundaries
- [Code of Conduct](../CODE_OF_CONDUCT.md) — participation and enforcement
- [Security policy](../SECURITY.md) — private reporting, scope, safe harbor,
  response targets, and known limitations
- [Roadmap](../ROADMAP.md) — staged, gated, and exploratory milestones without
  delivery-date or activation claims
- [Citation metadata](../CITATION.cff) — cite the reviewed `v0.7.9` release, or
  include the exact commit SHA when discussing later unreleased source

No donation or sponsorship program is represented by repository metadata at
this time. Hosted pilots, enterprise scope, and support terms require separate
commissioning and written agreement.

## Machine-readable and publishing surfaces

- [`llms.txt`](llms.txt) and [`llms-full.txt`](llms-full.txt) mirror public product guidance for language-model consumers.
- [`index.html`](index.html) and related assets are legacy static-site sources. The
  standalone `pricing.html` and `waitlist.html` files are legacy snapshots, not
  redirects or an independent product or entitlement contract. The active product
  surface is the Next.js `/pricing` route; the legacy pages are excluded from the
  static sitemap.
- [`blog-launch.md`](blog-launch.md), [`blog-devto.md`](blog-devto.md), and [`hn-submission.md`](hn-submission.md) are launch/publishing drafts, not normative technical specifications.

When behavior conflicts with prose, treat code, closed schemas, tests, and release automation as authoritative and open a documentation issue. Avoid copying capability counts or platform promises into new documents unless an automated check enforces them.
