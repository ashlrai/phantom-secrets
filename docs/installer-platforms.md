# Unix installer platform detection

[`scripts/install.sh`](../scripts/install.sh) selects a release archive from
the exact, case-sensitive output of `uname -s` and `uname -m`. It checks for
`curl` and `tar` and validates any install-directory override first. It then
checks the OS before the architecture, prints the selected target, and only
afterward creates the install parent, acquires a lock, and downloads an archive.

| `uname -s` | OS part of target |
|---|---|
| `Darwin` | `apple-darwin` |
| `Linux` | `unknown-linux-gnu` |
| Any other value | Error: `unsupported OS` |

| `uname -m` | Architecture part of target |
|---|---|
| `x86_64` or `amd64` | `x86_64` |
| `arm64` or `aarch64` | `aarch64` |
| Any other value | Error: `unsupported arch` |

The four resulting targets and archive names are:

| OS | Architecture aliases | Target | Archive |
|---|---|---|---|
| `Darwin` | `x86_64`, `amd64` | `x86_64-apple-darwin` | `phantom-x86_64-apple-darwin.tar.gz` |
| `Darwin` | `arm64`, `aarch64` | `aarch64-apple-darwin` | `phantom-aarch64-apple-darwin.tar.gz` |
| `Linux` | `x86_64`, `amd64` | `x86_64-unknown-linux-gnu` | `phantom-x86_64-unknown-linux-gnu.tar.gz` |
| `Linux` | `arm64`, `aarch64` | `aarch64-unknown-linux-gnu` | `phantom-aarch64-unknown-linux-gnu.tar.gz` |

For example, FreeBSD and a Windows `uname -s` value are rejected as
unsupported OSes; `i686` and `riscv64` are rejected as unsupported
architectures. If both are unsupported, the OS error comes first. The error
directs users to the release page for a checksum-verifiable asset; it does not
guarantee that an asset for the rejected platform exists. Native Windows uses
the separate [PowerShell installer](../scripts/install.ps1).

Linux detection does not inspect the C library: a musl-based system still
selects the GNU archive, which may not run there. Likewise, a selected target
does not establish binary compatibility, asset availability, or native test
coverage. See [platform support](platform-support.md) for the GNU/Linux
baseline and release evidence, and [installer staging](installer-staging.md)
for verification and installation behavior.
