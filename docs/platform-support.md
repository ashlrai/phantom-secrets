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
documentation tranche. The immutable `v0.7.4` GitHub release has separate
six-target native-release acceptance; that does not validate the npm wrapper
installation path, whose `0.7.4` candidate failed on all six targets. The
release-state snapshot below was verified 2026-09-02 before any `v0.7.5`
publication; at that snapshot the `0.7.5` fix-forward had no native or
npm-channel acceptance receipt.

## Current matrix

| Target | Release build host and mode | GitHub release workflow | Primary npm wrapper | Shell installer | Configured native acceptance / current evidence |
|---|---:|---:|---:|---:|---:|
| macOS Apple Silicon (`aarch64-apple-darwin`) | `macos-latest` is currently an arm64 host; native-architecture build | Archive + SBOM configured | Mapped | Mapped | `v0.7.4` release-native acceptance passed on `macos-15` ARM64; npm `0.7.4` acceptance failed; no `0.7.5` receipt |
| macOS Intel (`x86_64-apple-darwin`) | Cross-target build on the current arm64 `macos-latest` host | Archive + SBOM configured | Mapped | Mapped | `v0.7.4` release-native acceptance passed on `macos-15-intel` X64; npm `0.7.4` acceptance failed; no `0.7.5` receipt |
| Linux ARM64 GNU (`aarch64-unknown-linux-gnu`) | Cross-compiled with `gcc-aarch64-linux-gnu` on x64 Ubuntu 22.04 | Archive + SBOM configured; GLIBC symbol ceiling enforced | Mapped | Mapped | `v0.7.4` release-native acceptance passed on `ubuntu-22.04-arm` ARM64; npm `0.7.4` acceptance failed; no `0.7.5` receipt |
| Linux x64 GNU (`x86_64-unknown-linux-gnu`) | Native-architecture build on x64 Ubuntu 22.04 | Archive + SBOM configured; GLIBC symbol ceiling enforced | Mapped | Mapped | `v0.7.4` release-native acceptance passed on `ubuntu-22.04` X64; npm `0.7.4` acceptance failed; no `0.7.5` receipt |
| Windows x64 MSVC (`x86_64-pc-windows-msvc`) | Native-architecture build on x64 `windows-latest` | ZIP + SBOM configured | Mapped | Mapped by `install.ps1` | `v0.7.4` release-native acceptance passed on `windows-latest` X64; npm `0.7.4` acceptance failed; no `0.7.5` receipt |
| Windows ARM64 MSVC (`aarch64-pc-windows-msvc`) | Native-architecture build on arm64 `windows-11-vs2026-arm` | ZIP + SBOM configured | Mapped | Mapped by `install.ps1` | `v0.7.4` release-native acceptance passed on `windows-11-vs2026-arm` ARM64; npm `0.7.4` acceptance failed; no `0.7.5` receipt |

The current workflow defines six target archives, each containing `phantom`
and `phantom-mcp`: four Unix `.tar.gz` files and two Windows `.zip` files. Both
npm wrappers and the direct installers share that six-target lookup contract.
The separate `npm-candidate-acceptance.yml` workflow is configured to exercise
the exact tagged five-file npm tarballs from fresh caches on these same six
native host classes before npm publication, then to repeat acceptance against
the integrity-pinned public `release-candidate` packages before either `latest`
tag changes. A workflow definition is not a receipt; retain all six successful
jobs for each mode.
The `native-acceptance` matrix is configured to download each exact build
artifact on its matching runner, reject extra or unsafe archive members, verify
archive integrity through extraction, assert the runner OS and architecture,
run both binaries' exact tagged `--version`, and complete the MCP stdio schema
smoke. It then runs the real direct installer from that exact local archive in
an isolated home/profile, validates both installed binaries and the source
receipt, injects a test-only failure immediately after candidate promotion,
and verifies that the sentinel-bearing accepted tree is restored with no
sibling transaction residue. It then corrupts the checksum sidecar and proves
that a pre-transaction integrity failure also preserves the accepted tree.
Windows acceptance suppresses persistent user-PATH mutation on the CI
account; it does not claim shell-profile acceptance. Attestation cannot begin
until all six jobs succeed. The exact `v0.7.4` tag workflow passed this release
native matrix and created the immutable GitHub release in
[run 33681798126](https://github.com/ashlrai/phantom-secrets/actions/runs/33681798126).
That receipt does not prove npm-wrapper installation: exact npm `0.7.4`
acceptance failed independently. At the 2026-09-02 pre-publication snapshot, no
exact `v0.7.5` candidate receipt existed.

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
| Provider issuance/enrollment/renewal/revocation | Hard-denied before credential/network access in 0.7.5 | Hard-denied before credential/network access in 0.7.5 | Hard-denied before credential/network access in 0.7.5 |
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
| Init review admission | Before vault provisioning, init retains the reviewed project root and exact dotenv/config leaf identity, bytes, and permissions; after locking it revalidates root and leaf snapshots before mutation | Source and deterministic decoy-test evidence, not a native credential-store run |
| Vault/project lock order | Vault/application authority is resolved before the project lock; stable root identity and exact config are revalidated afterward | Source and concurrency-test evidence, not native scheduler or credential-store acceptance |
| Effect status | `CommittedVerifiedButDurabilityUncertain` is committed and exactly verified, with a value-free warning/receipt and no rollback or retry; `CommittedButUncertain` is **Partial** when verification or durability remains unresolved | Partial outcomes require operator reconciliation and are not safe blind retries |
| Windows permissions before bytes | New private files/directories establish and verify a protected current-user DACL before content; replacements preserve and verify the reviewed exact DACL, inheritance state, and read-only state before bytes | Source-contract tests only; protected native Windows CI acceptance remains pending |
| Created-parent rollback | Identity-bound receipts remove only exact, empty transaction-created directories after descendant handles are dropped | Unknown creation state without a receipt remains explicitly unresolved |

Native credential-store and ACL source are likewise not acceptance. In
particular, mapping the `keyring` backend to Windows Credential Manager and
source-testing protected current-user DACL behavior do not prove that an exact
Windows archive passed those operations under a real user policy. That evidence
still requires protected native Windows CI against the exact candidate.

Provider-grant support in source does not prove that a provider application is
configured, consent completed, a credential accepted, renewal succeeded, or a
customer workflow passed. Use throwaway provider accounts for authorized native
acceptance and never place provider client secrets on the command line.

## Install methods

- The reviewed `v0.7.4` source build checks out
  `c20f4eb6d8272709985083afe156b5678a1ac054` and runs
  `cargo build --release --locked --bin phantom --bin phantom-mcp`. An unpinned
  crates.io install currently resolves the older `0.5.1` track.
- The npm packages' `latest` tags currently resolve `0.6.0`. Exact `0.7.4`
  wrappers exist only under `release-candidate` and failed the six-target npm
  acceptance gate; they are not the reviewed `v0.7.4` GitHub/Homebrew path.
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

The release workflow automates steps 1 and 2, a bounded portion of step 3
(fresh direct install, receipt validation, post-promotion rollback, and
checksum-failure preservation), and MCP schema initialization from step 5 on
all six native runners. Upgrade,
interruption, cache recovery, persistent PATH/shell behavior, credential stores,
an authenticated proxy request, editors, and platform trust still require
separately retained evidence. No repository-local source test or workflow
definition is a substitute for a successful exact-candidate run and those
additional receipts.

## External benchmark

Phantom's [Rama-derived engineering standard](rama-design-standard.md) pins the
upstream main snapshot
[`267e4790c899736e6f60d982c8a0932406d4079e`](https://github.com/plabayo/rama/commit/267e4790c899736e6f60d982c8a0932406d4079e),
reviewed 2026-09-01. Rama's explicit stacks, modular crates, runnable examples,
and tiered platform CI are benchmarks for improving Phantom's engineering
evidence. Rama is not a dependency, and its platform tiers or features do not
transfer to Phantom.
