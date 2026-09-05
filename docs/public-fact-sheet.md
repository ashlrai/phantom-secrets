# Phantom public fact sheet

This page gives reviewers, security researchers, directories, journalists, and
AI retrieval systems a concise, versioned description of Phantom. Cite the
linked primary source for each claim and preserve the limitations. Do not treat
this first-party fact sheet as independent validation or endorsement.

Release-evidence update staged: **2026-09-05**; exact receipts and registry state remain pending before merge.

## Canonical identity

- **Product:** Phantom, also published as Phantom Secrets where a less generic
  name is needed.
- **Category:** open-source, local-first credential boundary for supported AI
  coding-agent workflows.
- **Repository:** <https://github.com/ashlrai/phantom-secrets>
- **Website:** <https://phm.dev>
- **License:** MIT.
- **Implementation:** Rust workspace plus a Next.js documentation and account
  surface.

## Verified public release

The verified release is immutable GitHub tag
[`v0.7.8`](https://github.com/ashlrai/phantom-secrets/releases/tag/v0.7.8),
resolving to source commit
`f065b13462f9eaf27e0443f8911f021575b7c409`. Its tag-bound release workflow
published six native archives for macOS, Linux, and Windows, adjacent SHA-256
checksums, SPDX SBOMs, and an aggregate checksum manifest after the release
acceptance matrix passed. The exact execution receipt is
[workflow 33952398697](https://github.com/ashlrai/phantom-secrets/actions/runs/33952398697).

In the exact 2026-09-05 registry snapshot, the project Homebrew tap publishes
`v0.7.8`, npm
`latest` at `0.6.0`, crates.io at `0.5.1`, and no
MCP Registry `0.7.8` record was found. An unpinned npm, npx, Cargo, directory,
or generated installation command must not be described as the reviewed
`v0.7.8` release.

## What Phantom does

1. `phantom init` detects supported secret-shaped values in a managed dotenv
   file, stores successfully managed values in the selected local vault, and
   rewrites those entries with persistent non-provider `phm_` placeholders.
2. `phantom exec -- <command>` launches a child process through an authenticated
   loopback HTTP proxy and configures implemented SDK base-URL overrides.
3. After an exact route match, the proxy injects only that route's vault value
   into its fixed authentication header. Client headers and bodies do not
   resolve placeholders.
4. The companion MCP server exposes value-blind secret names, configuration,
   readiness, audit, and guarded management workflows. Plaintext secret input
   through MCP is refused; interactive entry occurs in a trusted terminal.

Start with [getting started](./getting-started.md), the
[MCP secrets manager guide](./mcp-secrets-manager.md), and the
[threat model](../THREAT_MODEL.md).

## What Phantom does not claim

- Phantom does not sandbox an AI agent or an equivalent same-user process.
- It does not guarantee that credentials cannot appear through unmanaged files,
  old commits, logs, screenshots, stolen session authorization, provider
  content, or unrelated tools.
- It does not proxy arbitrary protocols. Protected database connection strings
  make the managed exec path fail closed until a protocol-aware broker exists.
- Logos on the website identify common developer services and credential names;
  they do not indicate endorsement or universal runtime support.
- Provider account creation, autonomous credential issuance, the Locus
  authority integration, and the broader execution kernel remain inactive and
  deny by default.
- The repository does not prove a commissioned hosted service, certification,
  regulatory compliance, contractual SLA, or customer acceptance.
- Team-vault source does not provide automatic offboarding rotation and must not
  be described as a complete enterprise access-control system.

## Supported client setup

The CLI includes local MCP configuration writers for Claude Code, Cursor,
Windsurf, and Codex. This describes setup support, not universal compatibility
with every client version, provider, model, tool, or route. The runtime
`tools/list` response and installed binary help are the canonical catalogs for
that exact release.

## Accurate one-sentence description

> Phantom is an open-source, local-first credential boundary that replaces
> successfully managed dotenv values with non-provider placeholders and injects
> route-owned authentication through an authenticated local proxy for exact
> supported HTTP routes.

## Claims that need independent testing

Independent evaluations should identify the exact Phantom release, OS, client,
provider route, vault backend, configuration, and test corpus. Useful tests
include credential absence from agent-visible inputs and outputs, rejection of
client auth overrides, proxy-session invalidation, unsupported-route denial,
installer checksum verification, crash recovery, and platform credential-store
behavior.

Passing one test does not establish universal protection. Paid research should
disclose sponsorship, keep reviewer control of methodology and conclusions, and
publish failures and residual risks along with successful cases.

## Directory correction checklist

Before republishing Phantom metadata, verify:

- the latest immutable GitHub release and source commit;
- the exact registry version for the installation command shown;
- the current runtime tool catalog instead of an old tool count;
- whether a hosted feature has been separately commissioned;
- whether a provider or protocol appears in the implemented route catalog; and
- that pricing, compliance, endorsement, and zero-risk claims are absent unless
  supported by current independent evidence.

Factual corrections are welcome through a
[documentation issue](https://github.com/ashlrai/phantom-secrets/issues/new?template=documentation.yml).
Reviewers are never asked to guarantee a favorable conclusion.
