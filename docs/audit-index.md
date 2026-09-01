# Security and audit index

This page is the shortest path for maintainers and third-party reviewers to
Phantom's canonical security, architecture, testing, platform, and release
evidence. It links sources instead of copying them into a point-in-time audit
packet.

## Current activation decision

The shipped secret-protection CLI, vault, proxy, MCP, cloud-client, and web
source are separate from the governed execution-kernel foundations. The local
Unix workspace setup transaction is the only functional execution-kernel
slice. Locus authority, the native broker, production engineering execution,
and externally trusted execution receipts must remain inactive.

The shipped `phantom grant` CLI exposes value-free metadata and compatibility
commands, not live provider issuance. Version 0.7.4 hard-denies enrollment,
refresh, renewal, rotation, and remote revocation before credential access and
network I/O. Historical **provider-grant** records are not execution-kernel
**authority grants** and do not activate Locus, a broker lease, or engineering
execution.

That is a source-level decision. It does not attest to the deployed website,
an unpublished artifact, a provider configuration, or a customer environment.

## Canonical review map

| Review question | Canonical source |
|---|---|
| What runs today, and where are the trust boundaries? | [Architecture](architecture.md) |
| What assets, actors, mitigations, and non-mitigations exist? | [Threat model](../THREAT_MODEL.md) |
| How should a vulnerability be reported, and what is in scope? | [Security policy](../SECURITY.md) |
| What is supported on macOS, Linux, and Windows? | [Platform support](platform-support.md) |
| What makes a source candidate or artifact release-ready? | [Release and readiness guide](release-readiness.md) |
| What blocks execution-kernel activation? | [Architecture](architecture.md) and [threat model](../THREAT_MODEL.md) |
| How are contributors expected to build and test? | [Contributing guide](../CONTRIBUTING.md) |
| What do CI and release automation enforce? | [`ci.yml`](../.github/workflows/ci.yml) and [`release.yml`](../.github/workflows/release.yml) |
| What is the current provider-denial contract? | [Provider-grant specification](grants-spec.md), with the [historical, non-executable design contract](../ISSUANCE_CONTRACT.md) retained separately |
| What changed between versions? | [Changelog](../CHANGELOG.md) and immutable Git history |
| What dependencies and packages compose the Rust workspace? | [`Cargo.toml`](../Cargo.toml), [`Cargo.lock`](../Cargo.lock), and crate manifests |
| What web dependencies and scripts are selected? | [`apps/web/package.json`](../apps/web/package.json) and [`apps/web/package-lock.json`](../apps/web/package-lock.json) |
| Which external network-engineering benchmark is pinned? | [Rama-derived engineering standard](rama-design-standard.md), pinned to upstream main `267e4790c899736e6f60d982c8a0932406d4079e` as reviewed 2026-09-01 |

## 2026-09-01 retained-filesystem source review

This review documents the retained-root and exact-effect implementation. It is
a source review, not an immutable release, native-platform, deployment,
provider, or customer attestation.

| Field | Value |
|---|---|
| Repository | `ashlrai/phantom-secrets` |
| Branch | `codex/public-claim-truth` |
| Implementation-security SHA | `5a3edad60634c78af3079f588bf51fefa0b69586` |
| Documentation commit | The later commit containing this file; it records prose/manifest descriptions and must not be substituted for the implementation SHA above |
| Working-tree boundary during reconciliation | `5a3edad60634c78af3079f588bf51fefa0b69586` is the implementation-security identity. Other concurrent uncommitted implementation, release-workflow/readiness, and documentation edits in the shared working tree are not part of that SHA or this source-review identity |
| Reviewed implementation | Retained anchored effects, exact init root/leaf admission, Windows pre-byte ACL establishment/preservation, typed effect outcomes, CLI/MCP governed mutation paths, vault-before-project lock order, Git-hook authorization, and project/global editor setup |
| Excluded evidence | No exact `0.7.4` archive, native Windows/macOS/Linux run, publication, deployment, provider activation, enterprise commissioning, or customer acceptance receipt was inspected |

Primary source paths for this review:

- [`anchored.rs`](../crates/phantom-core/src/fs/anchored.rs) — retained
  directories/targets, identity-bound reads, single-link checks, exact writes
  and unlinks, Windows ACL enforcement before content bytes, directory receipts,
  and the three typed effect outcomes;
- [`transaction_lock.rs`](../crates/phantom-vault/src/transaction_lock.rs) and
  [`init_transaction.rs`](../crates/phantom-vault/src/init_transaction.rs) —
  acquisition-time project-root authority, project-relative targets, exact
  init leaf snapshots, and identity-bound rollback;
- [`precommit_hook.rs`](../crates/phantom-core/src/precommit_hook.rs) — effective
  Git hook authority and fail-closed external-root handling; and
- [`setup.rs`](../crates/phantom-cli/src/commands/setup.rs) — separate project
  and global client-config authorities, private parent receipts, and stable
  setup coordination under Phantom application state;
- [`workspace.rs`](../crates/phantom-cli/src/commands/workspace.rs),
  [`rotate.rs`](../crates/phantom-cli/src/commands/rotate.rs), and
  [`server.rs`](../crates/phantom-mcp/src/server.rs) — vault/application
  authority before project-lock acquisition, retained root-identity comparison,
  and exact post-lock config revalidation; and
- [`mcp_approve.rs`](../crates/phantom-cli/src/commands/mcp_approve.rs) —
  noninteractive terminal denial before approval inspection, challenge
  generation, or stdin reads.

Unix rename-and-decoy tests exercise path-swap behavior, including exact init
root/leaf admission and byte-identical replacement leaves. Windows
implementation and contract tests for protected current-user DACL
establishment/preservation before bytes were inspected in source, but no exact
Windows archive was run in protected native CI. Credential Manager and ACL
behavior remain source contracts, not native acceptance.

The earlier implementation SHA
`1e6ce2fb7bfa1ce9c430f8d0bf704e159ed50834` reported 490/490 `phantom-cli`
tests in the PTY harness, strict `phantom-cli` Clippy, workspace formatting, and
diff checks passing. That result must not be relabeled as validation of the later
security SHA `5a3edad60634c78af3079f588bf51fefa0b69586`. No immutable CI or
native-archive log for `5a3edad` is embedded in this documentation, so source
inspection and documentation gates remain distinct from publication, native
acceptance, deployment, provider, and customer evidence.

### Live repository-governance observation — 2026-09-01

As separately inspected on 2026-09-01, the GitHub `release` environment had a
required reviewer and a deployment policy limited to `v*` tags. Immutable tag
ruleset `21903888` covered update, deletion, and non-fast-forward changes with
no bypass. Separate creation ruleset `21997435` covered tag creation with a
Mason-only bypass. Creation authority therefore cannot bypass the independent
no-bypass immutability ruleset. This dated live-setting observation is not part
of implementation SHA `5a3edad60634c78af3079f588bf51fefa0b69586`, does not
authorize a release, and must be reverified before a tag is created.

## 2026-08-30 local documentation-review identity

The 2026-08-30 review is a working-tree review, not an immutable release
attestation. Its repository identity at this documentation review was:

| Field | Value |
|---|---|
| Repository | `ashlrai/phantom-secrets`; local checkout root returned by `git rev-parse --show-toplevel` |
| Branch | `codex/phantom-integration-20260830` |
| Base `HEAD` | `27f94e98fb83880a4fe74143bb45ec4bba27f710` |
| Dirty state | Dirty, with tracked and untracked activation, packaging, web, and documentation work |
| Reviewed scope | Provider issuance and `grant` CLI behavior, execution-kernel and workspace status, MCP facade, current release workflow, npm wrapper contract, Homebrew metadata, issue templates, and canonical documentation |

Because the tree was dirty and evolving, the base `HEAD` is not a content
identity for the reviewed files. Before using the findings for a release,
repeat the review against a clean exact SHA and immutable artifacts, then record
passed, failed, ignored, skipped, and externally blocked checks.

Capture a fresh repository identity with:

```bash
git rev-parse --show-toplevel
git branch --show-current
git rev-parse HEAD
git status --short
```

## Evidence layers

Use the narrowest accurate claim in an audit report:

| Evidence | Supported statement |
|---|---|
| Design document | Proposed behavior and intended boundary. |
| Source inspection | Behavior implemented in the inspected tree. |
| Focused automated test | The named behavior passed in that harness and environment. |
| Committed verified durability warning | `CommittedVerifiedButDurabilityUncertain` means the live namespace effect committed and exact post-publish verification succeeded, but directory crash durability is not provable. It is success with a value-free warning/receipt, not a rollback or retry signal. |
| Partial effect receipt | `CommittedButUncertain` means the namespace effect may have committed, but durability or final verification remains unresolved. It requires reconciliation and is not proof of rollback or safe retry. |
| Full locked CI | The configured suite passed for the recorded commit and runners. |
| Built archive plus digest | The bytes were produced and integrity metadata matches. |
| Native acceptance | The exact archive passed the named checks on one OS/architecture environment. |
| Deployment receipt | The exact immutable artifact was deployed to the named environment. |
| Provider check | The separately authorized provider accepted the named operation. |
| User/customer acceptance | The named real workflow passed in the named environment. |

Never convert one row into the next without its own evidence.

## Open review themes

Reviewers should pay particular attention to these unresolved boundaries:

- no coherent, compatible, signed Locus authority artifact or
  peer-authenticated cross-platform transport;
- no production OS-confinement backend or trusted workspace/toolchain handle
  minters;
- no host-protected monotonic rollback anchor for replay state;
- local HMAC integrity that does not resist a fully compromised same-user
  account and does not create externally trusted receipts;
- retained path capabilities protect governed operations from ambient
  rename/decoy redirection but do not sandbox a process with equivalent
  same-user filesystem or terminal authority;
- verified effects without provable directory crash durability are committed
  successes with explicit warnings, while `CommittedButUncertain` effects
  require reconciliation;
- provider enrollment, issuance, refresh, renewal, rotation, and remote
  revocation are not active; shipped paths fail before credential or network
  access, while exact test mocks prove local scaffolding only; and
- the reviewed `v0.7.3` release is distinct from staged `0.7.4` source. The
  staged workflow defines per-artifact checksums, SBOM/provenance bindings, and
  a six-target candidate matrix, but those definitions do not prove that exact
  archives ran or passed on native runners. Independent signatures, native code
  signing/notarization, and six-target exact-archive acceptance remain open.

The inactive components deny production use while these activation findings
remain open. Do not work around that denial with test constructors, caller
paths, ambient credentials, a reveal command, or stdout capture.

## Reproducible repository checks

The canonical source commands are maintained in the
[contributing guide](../CONTRIBUTING.md) and
[release-readiness guide](release-readiness.md). A formal audit should record at
least:

- locked workspace tests, formatting, and all-target Clippy;
- both npm wrapper tests and package-content checks, version parity, MCP stdio
  and schema smoke, and the exact-artifact contract checks enforced by release
  automation;
- web clean install, dependency audit, tests, and production build when web
  source changed;
- scoped static analysis and secret scanning, including tool versions and
  allowlists;
- ignored tests and why they require a native keychain or authorized external
  account;
- unavailable tools such as a dependency-advisory scanner as blocked, not
  silently passed; and
- `git diff --check`, documentation links, and path validation for the reviewed
  tree.

Do not install missing scanners, initialize services, or access live provider
accounts solely to make an audit appear complete unless that scope is
explicitly authorized.

## Formal audit packet checklist

A release or third-party audit packet should contain:

1. timestamp, verifier, repository, branch, full source SHA, and clean/dirty
   state;
2. reviewed files, excluded files, and external systems not inspected;
3. tool versions, commands, exit results, and immutable log locations;
4. a claim register with severity, file and line, claim, evidence, layer,
   impact, and smallest correction;
5. exact archives, digests, signatures, SBOMs, and provenance attestations;
6. native acceptance evidence by operating system and architecture;
7. deployment, migration, feature-flag, provider, and customer evidence as
   separate sections;
8. known limitations, owners, due dates, and activation consequences; and
9. last known-good artifact plus authorized rollback and reconciliation plan.

The absence of live-system or customer evidence is acceptable when it is stated
clearly. It must not be filled with an inference from local source or CI.

## Ownership and update triggers

- Architecture owners update the architecture and threat model when a trust
  boundary, public constructor, transport, credential seam, or lifecycle
  changes.
- Release owners update automation, the platform matrix, and release guide in
  the same change when targets, artifacts, signing, or publication changes.
- Security owners append a dated audit or advisory; they do not rewrite an old
  snapshot to describe a new source candidate.
- Feature owners update contributor and user documentation when setup,
  configuration, operation, or recovery changes.

If a document conflicts with current code, schemas, tests, or immutable build
evidence, record the conflict and correct the documentation. Do not treat prose
as proof of behavior.
