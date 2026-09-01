# Platform support

This matrix separates source compilation, release packaging, installer or
wrapper mapping, and native acceptance. One does not prove the next.

## Evidence vocabulary

| Layer | What it proves |
|---|---|
| Source contract | The inspected implementation and tests express the named invariant. It may be compiled or inspected for another target without running there. |
| Workflow configuration | Automation is configured to request the named target/check. It does not prove that a run started or passed. |
| Cross-compiled artifact | A host produced bytes for another target. It does not prove that the target OS loaded or exercised them. |
| Native acceptance | The exact identified archive passed the named checks on the matching OS and architecture, with a retained receipt. |

The filesystem hardening described below is source-contract evidence in this
documentation tranche. It is not native acceptance for macOS, Linux, or
Windows, and it is not evidence that a `0.7.4` artifact was published.

## Current matrix

| Target | Release build host and mode | GitHub release workflow | Primary npm wrapper | Shell installer | Configured native acceptance / current evidence |
|---|---:|---:|---:|---:|---:|
| macOS Apple Silicon (`aarch64-apple-darwin`) | `macos-latest` is currently an arm64 host; native-architecture build | Archive + SBOM configured | Mapped | Mapped | Configured on `macos-15` ARM64: exact archive, OS/arch, both versions, and MCP smoke; no exact v0.7.4 candidate receipt recorded |
| macOS Intel (`x86_64-apple-darwin`) | Cross-target build on the current arm64 `macos-latest` host | Archive + SBOM configured | Mapped | Mapped | Configured on `macos-15-intel` X64: exact archive, OS/arch, both versions, and MCP smoke; no exact v0.7.4 candidate receipt recorded |
| Linux ARM64 GNU (`aarch64-unknown-linux-gnu`) | Cross-compiled with `gcc-aarch64-linux-gnu` on x64 Ubuntu 22.04 | Archive + SBOM configured; GLIBC symbol ceiling enforced | Mapped | Mapped | Configured on `ubuntu-22.04-arm` ARM64: exact archive, OS/arch, both versions, and MCP smoke; no exact v0.7.4 candidate receipt recorded |
| Linux x64 GNU (`x86_64-unknown-linux-gnu`) | Native-architecture build on x64 Ubuntu 22.04 | Archive + SBOM configured; GLIBC symbol ceiling enforced | Mapped | Mapped | Configured on `ubuntu-22.04` X64: exact archive, OS/arch, both versions, and MCP smoke; no exact v0.7.4 candidate receipt recorded |
| Windows x64 MSVC (`x86_64-pc-windows-msvc`) | Native-architecture build on x64 `windows-latest` | ZIP + SBOM configured | Mapped | Mapped by `install.ps1` | Configured on `windows-latest` X64: exact archive, OS/arch, both versions, and MCP smoke; no exact v0.7.4 candidate receipt recorded |
| Windows ARM64 MSVC (`aarch64-pc-windows-msvc`) | Native-architecture build on arm64 `windows-11-vs2026-arm` | ZIP + SBOM configured | Mapped | Mapped by `install.ps1` | Configured on `windows-11-vs2026-arm` ARM64: exact archive, OS/arch, both versions, and MCP smoke; no exact v0.7.4 candidate receipt recorded |

The current workflow defines six target archives, each containing `phantom`
and `phantom-mcp`: four Unix `.tar.gz` files and two Windows `.zip` files. Both
npm wrappers and the direct installers share that six-target lookup contract.
The `native-acceptance` matrix is configured to download each exact build
artifact on its matching runner, reject extra or unsafe archive members, verify
archive integrity through extraction, assert the runner OS and architecture,
run both binaries' exact tagged `--version`, and complete the MCP stdio schema
smoke. Attestation cannot begin until all six jobs succeed. That workflow
definition is not evidence that a corresponding release artifact exists, is
signed, or passed a particular run: no exact v0.7.4 candidate receipt is
recorded yet.

GitHub's current [hosted-runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
maps `windows-latest` to x64 and `macos-latest` to arm64. GNU/Linux release
builds use the explicit `ubuntu-22.04` x64 image rather than a moving
`ubuntu-latest` label. The workflow's Windows ARM64 jobs use the literal
`windows-11-vs2026-arm` label. Runner labels and images can change, so the run
log and image metadata are the source of truth for a particular release. A
native-architecture compilation host is not native acceptance on its own. The
separate matrix is configured to execute the exact resulting archive; only a
retained successful run establishes that evidence for a particular candidate.

## GNU/Linux compatibility baseline

The oldest GNU/Linux userspace targeted by the release workflow is Ubuntu 22.04,
whose baseline GNU C Library is GLIBC 2.35. After building each x64 and ARM64 GNU
target, the workflow reads the ELF version requirements of both `phantom` and
`phantom-mcp` and fails if the highest numeric requirement exceeds
`GLIBC_2.35`. It also fails closed when it cannot read numeric GLIBC evidence or
encounters an unknown GLIBC requirement.

This is a deterministic symbol-version ceiling, not a claim that every Linux
distribution with GLIBC 2.35 is compatible. The GLIBC build gate itself does
not test the packaged archive, ARM64 execution, the kernel, loader, native
credential store, proxy, or MCP behavior. It does not constitute native runtime acceptance.
The separate native matrix is configured to cover exact-archive
execution and MCP schema initialization on Linux x64 and ARM64, but its source
definition is not a successful candidate receipt and it does not cover the
remaining operating-system integrations below.

## Feature-specific boundaries

| Feature | macOS | Linux | Windows |
|---|---|---|---|
| Core CLI, vault, proxy, MCP source | Implemented | Implemented | Implemented |
| Native credential store | Keychain integration | Secret Service/keyring integration, with encrypted-file fallback | Credential Manager integration |
| Provider-grant design source and value-free metadata | Present | Present | Present |
| Provider issuance/enrollment/renewal/revocation | Hard-denied before credential/network access in 0.7.4 | Hard-denied before credential/network access in 0.7.4 | Hard-denied before credential/network access in 0.7.4 |
| Workspace inspect/propose/request | Implemented | Implemented | Inspect/propose only |
| Durable workspace apply | Descriptor-relative Unix implementation | Descriptor-relative Unix implementation | Fails closed |
| Durable broker replay foundation | Unix implementation | Unix implementation | Fails closed |
| Production confined engineering runtime | Unavailable | Unavailable | Unavailable |

### Governed filesystem mutation

| Contract | Current source evidence | Acceptance boundary |
|---|---|---|
| Retained root/parent identity | Project and explicitly authorized global config writers resolve targets from retained directory capabilities; Unix rename-and-decoy tests preserve the replacement decoy | No exact native-archive receipt is recorded |
| Symlink and reparse denial | No-follow traversal rejects symlink/reparse ancestors and leaf targets; Windows implementation has source-contract checks | Windows tests in source are not a native Windows run |
| Hard-link denial | Sensitive anchored files must be regular and have one link before read/effect | Platform filesystem behavior still needs exact native acceptance |
| Exact compare-and-swap | Before-images bind stable file identity and bytes; same-content replacement identities are rejected | Covers cooperating Phantom operations, not arbitrary same-user writers |
| Vault/project lock order | Vault/application authority is resolved before the project lock; stable root identity and exact config are revalidated afterward | Source and concurrency-test evidence, not native scheduler or credential-store acceptance |
| Effect status | Durable completion is distinct from `CommittedButUncertain` (**Partial**) after a namespace effect but failed durability/verification | Partial outcomes require operator reconciliation and are not safe blind retries |
| Created-parent rollback | Identity-bound receipts remove only exact, empty transaction-created directories after descendant handles are dropped | Unknown creation state without a receipt remains explicitly unresolved |

Native credential-store source is likewise not acceptance. In particular,
mapping the `keyring` backend to Windows Credential Manager does not prove that
an exact Windows binary stored, read, prompted for, or removed a credential
under a real user policy.

Provider-grant support in source does not prove that a provider application is
configured, consent completed, a credential accepted, renewal succeeded, or a
customer workflow passed. Use throwaway provider accounts for authorized native
acceptance and never place provider client secrets on the command line.

## Install methods

- The reviewed `v0.7.3` source build checks out
  `cffd0f29ab85a45358f011fdcfd40667d576c420` and runs
  `cargo build --release --locked --bin phantom --bin phantom-mcp`. An unpinned
  crates.io install currently resolves the older `0.5.1` track.
- The npm packages currently resolve `0.6.0`, not the reviewed `v0.7.3`
  release. A wrapper mapping also depends on a matching published archive.
- `scripts/install.sh` supports macOS and GNU Linux targets. Native Windows uses
  `scripts/install.ps1`; both scripts verify bounded HTTPS downloads, strict
  sidecar checksums, archive shape, and binary identity before promotion.
- The Homebrew formula is a manually reviewed distribution surface. The
  repository's release workflow does not automatically update a tap.

## Configured and additional native acceptance

Before claiming a target as release-ready, test the exact archive and digest on
that target:

1. validate the archive has exactly the expected two regular files;
2. verify the published checksum and exact `--version` output for both binaries;
3. run install, upgrade, interruption, rollback, and cache-recovery paths;
4. exercise the native credential store and encrypted-file fallback;
5. run an authenticated loopback proxy request and MCP stdio initialization;
6. exercise supported shells and editor setup; and
7. record code-signing, notarization, or platform trust results separately.

The release workflow automates steps 1 and 2 plus MCP schema initialization from
step 5 on all six native runners. Installer and upgrade behavior, credential
stores, an authenticated proxy request, shells and editors, and platform trust
still require separately retained evidence. No repository-local source test or
workflow definition is a substitute for a successful exact-candidate run and
those additional receipts.

## External benchmark

Phantom's [Rama-derived engineering standard](rama-design-standard.md) pins the
upstream main snapshot
[`267e4790c899736e6f60d982c8a0932406d4079e`](https://github.com/plabayo/rama/commit/267e4790c899736e6f60d982c8a0932406d4079e),
reviewed 2026-09-01. Rama's explicit stacks, modular crates, runnable examples,
and tiered platform CI are benchmarks for improving Phantom's engineering
evidence. Rama is not a dependency, and its platform tiers or features do not
transfer to Phantom.
