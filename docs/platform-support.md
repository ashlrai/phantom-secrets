# Platform support

This matrix separates source compilation, release packaging, installer or
wrapper mapping, and native acceptance. One does not prove the next.

## Current matrix

| Target | Release build host and mode | GitHub release workflow | Primary npm wrapper | Shell installer | Native acceptance in this repository |
|---|---:|---:|---:|---:|---:|
| macOS Apple Silicon (`aarch64-apple-darwin`) | `macos-latest` is currently an arm64 host; native-architecture build, no archive execution | Archive + SBOM configured | Mapped | Mapped | Not recorded for the exact candidate archive |
| macOS Intel (`x86_64-apple-darwin`) | Cross-target build on the current arm64 `macos-latest` host; no Intel execution | Archive + SBOM configured | Mapped | Mapped | Not recorded for the exact candidate archive |
| Linux ARM64 GNU (`aarch64-unknown-linux-gnu`) | Cross-compiled with `gcc-aarch64-linux-gnu` on x64 Ubuntu 22.04; no ARM execution | Archive + SBOM configured; GLIBC symbol ceiling enforced | Mapped | Mapped | Not recorded for the exact candidate archive |
| Linux x64 GNU (`x86_64-unknown-linux-gnu`) | Native-architecture build on x64 Ubuntu 22.04, no archive execution | Archive + SBOM configured; GLIBC symbol ceiling enforced | Mapped | Mapped | Not recorded for the exact candidate archive |
| Windows x64 MSVC (`x86_64-pc-windows-msvc`) | Native-architecture build on x64 `windows-latest`, no archive execution | ZIP + SBOM configured | Mapped | Mapped by `install.ps1` | Not recorded for the exact candidate archive |
| Windows ARM64 MSVC (`aarch64-pc-windows-msvc`) | Native-architecture build on arm64 `windows-11-vs2026-arm`, no archive execution | ZIP + SBOM configured | Mapped | Mapped by `install.ps1` | Not recorded for the exact candidate archive |

The current workflow defines six target archives, each containing `phantom`
and `phantom-mcp`: four Unix `.tar.gz` files and two Windows `.zip` files. Both
npm wrappers and the direct installers share that six-target lookup contract.
A mapping or workflow definition is not evidence that a corresponding release
artifact exists, is signed, or passed native acceptance.

GitHub's current [hosted-runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
maps `windows-latest` to x64 and `macos-latest` to arm64. GNU/Linux release
builds use the explicit `ubuntu-22.04` x64 image rather than a moving
`ubuntu-latest` label. The workflow's Windows ARM64 jobs use the literal
`windows-11-vs2026-arm` label. Runner labels and images can change, so the run
log and image metadata are the source of truth for a particular release. A
native-architecture compilation host is still not native acceptance because the
workflow packages but does not execute the exact resulting archive.

## GNU/Linux compatibility baseline

The oldest GNU/Linux userspace targeted by the release workflow is Ubuntu 22.04,
whose baseline GNU C Library is GLIBC 2.35. After building each x64 and ARM64 GNU
target, the workflow reads the ELF version requirements of both `phantom` and
`phantom-mcp` and fails if the highest numeric requirement exceeds
`GLIBC_2.35`. It also fails closed when it cannot read numeric GLIBC evidence or
encounters an unknown GLIBC requirement.

This is a deterministic symbol-version ceiling, not a claim that every Linux
distribution with GLIBC 2.35 is compatible. It does not test the packaged
archive, ARM64 execution, the kernel, loader, native credential store, proxy, or
MCP behavior and does not constitute native runtime acceptance. Those remain
part of the exact-archive acceptance process below.

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

## Required native acceptance

Before claiming a target as release-ready, test the exact archive and digest on
that target:

1. validate the archive has exactly the expected two regular files;
2. verify the published checksum and exact `--version` output for both binaries;
3. run install, upgrade, interruption, rollback, and cache-recovery paths;
4. exercise the native credential store and encrypted-file fallback;
5. run an authenticated loopback proxy request and MCP stdio initialization;
6. exercise supported shells and editor setup; and
7. record code-signing, notarization, or platform trust results separately.

No repository-local source test is a substitute for that evidence.
