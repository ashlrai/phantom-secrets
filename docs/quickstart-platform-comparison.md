# Landing-page quickstart: platform comparison

The [install panel](https://phm.dev/#install) selects macOS initially; choose
Windows or Linux to see that platform's card. This comparison describes the
commands displayed by [`QuickStart.tsx`](../apps/web/src/components/landing/QuickStart.tsx).
The release tag, source commit, and installer digests are pinned in
[`public-release.ts`](../apps/web/src/lib/public-release.ts). Use the panel for
the current copyable commands and inspect its linked installer source before
running them.

| | macOS | Windows | Linux |
|---|---|---|---|
| Shell and installer | Bash, `install.sh` | PowerShell, `install.ps1` | Bash, `install.sh` |
| Linked archives | Apple Silicon: `phantom-aarch64-apple-darwin.tar.gz`; Intel: `phantom-x86_64-apple-darwin.tar.gz` | ARM64: `phantom-aarch64-pc-windows-msvc.zip`; x64: `phantom-x86_64-pc-windows-msvc.zip` | ARM64: `phantom-aarch64-unknown-linux-gnu.tar.gz`; x64: `phantom-x86_64-unknown-linux-gnu.tar.gz` |
| Script digest check | `shasum -a 256 -c -` | `Get-FileHash -Algorithm SHA256` | `sha256sum -c -` |
| Installed version checks | `~/.phantom-secrets/bin/phantom` and `phantom-mcp` | `$env:USERPROFILE\.phantom-secrets\bin\phantom.exe` and `phantom-mcp.exe` | `~/.phantom-secrets/bin/phantom` and `phantom-mcp` |

Each card links both architecture-specific archives and their SHA-256 sidecars.
The command downloads the script from the pinned source commit, checks its
fixed SHA-256 digest, and runs it only after verification succeeds. The
installer selects the architecture, verifies the archive's adjacent checksum,
two-binary shape, and versions, then promotes it to the user-owned install
directory. The command checks both installed binaries' versions; the next panel
also shows separate `phantom --version` and `phantom-mcp --version` checks on
PATH. The page's receipts are illustrative, and release evidence does not
establish every local shell or policy state.

## Temporary staging

On macOS and Linux the displayed command uses a subshell, `set -euo pipefail`,
and `umask 077`. It creates `phantom-install.XXXXXX` with `mktemp -d` under
`TMPDIR`, or `/tmp` if `TMPDIR` is unset or empty, and puts `install.sh` there.
Once installed, the exit trap attempts to remove the script and then the empty
directory, including on failure. Cleanup is best effort and is not guaranteed.
This temporary directory is not the install directory.

On Windows, PowerShell stops on errors and assigns a unique temporary
installer file under `$env:TEMP`; it does not create that Unix staging
directory. Its `finally` block attempts to remove the file even on failure;
removal is not guaranteed. These panel-level temporary locations are distinct
from the installer's own archive staging and promotion process; see
[Unix installer staging](installer-staging.md) for that process and its
recovery limits.

## Platform notes

- macOS selects Apple Silicon or Intel. The release is not notarized; inspect
  the pinned script and verify its checksum before any policy-dependent unblock.
- Windows selects ARM64 or x64. Archives are not Authenticode-signed; unblock
  only after checksum verification and when local policy permits it.
- Published Linux GNU targets enforce a glibc 2.35 symbol ceiling; musl and
  Alpine are not published.

For the full installation instructions and manual archive option, see
[getting started](getting-started.md#exact-github-assets-macos-linux-and-windows).
