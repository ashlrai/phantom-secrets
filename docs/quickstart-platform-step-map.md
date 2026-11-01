# Landing-page quickstart: platform step map

This map follows the [install panel](https://phm.dev/#install) in
[`QuickStart.tsx`](../apps/web/src/components/landing/QuickStart.tsx). The
[selector and card rendering](../apps/web/src/components/landing/QuickStart.tsx#L130-L199)
show macOS initially and one selected platform card at a time. Each card links
its installer source, two architecture archives, and their SHA-256 sidecars.
Use the page for the current copyable command; release identifiers and script
digests come from [`public-release.ts`](../apps/web/src/lib/public-release.ts).
Review the linked installer and the [full installation guide](getting-started.md#exact-github-assets-macos-linux-and-windows) before running it.

## Platform command

The card's command precedes the two numbered steps shared by all platforms.
The stages below describe the displayed command in execution order; cleanup is
attempted on exit, including failures, and is not guaranteed.

| Platform and source | Stage and download | Verify and install | Check and cleanup | Platform context |
|---|---|---|---|---|
| [macOS](../apps/web/src/components/landing/QuickStart.tsx#L40-L66) | Bash creates a private `mktemp -d` staging directory under `TMPDIR` or `/tmp`, installs an exit trap, and downloads `install.sh` from the pinned source. | `shasum -a 256 -c -` checks the script before `bash` runs it. The installer selects Apple Silicon or Intel. | Check both installed binaries' versions; the trap attempts to remove the script and empty staging directory. | Keychain when available; the release is not notarized. Inspect the pinned script and verify its checksum before any policy-dependent unblock. |
| [Windows](../apps/web/src/components/landing/QuickStart.tsx#L67-L100) | PowerShell stops on errors, chooses a unique temporary file under `$env:TEMP`, and downloads `install.ps1`. | `Get-FileHash -Algorithm SHA256` checks the script and a mismatch stops execution; the installer selects ARM64 or x64. | Check both installed executables' versions; `finally` attempts to remove the temporary file. | Current-user Credential Manager when available; archives are not Authenticode-signed. Unblock only after checksum verification and when local policy permits. |
| [Linux](../apps/web/src/components/landing/QuickStart.tsx#L101-L127) | Bash creates a private `mktemp -d` staging directory under `TMPDIR` or `/tmp`, installs an exit trap, and downloads `install.sh` from the pinned source. | `sha256sum -c -` checks the script before `bash` runs it. The published targets are ARM64 and x64 GNU. | Check both installed binaries' versions; the trap attempts to remove the script and empty staging directory. | GNU targets enforce a glibc 2.35 symbol ceiling; musl and Alpine are not published. Keyutils is initially session-persistent, not reboot-persistent; desktop users can migrate to Secret Service, while headless encrypted-file use needs a managed passphrase. |

The [installation note](../apps/web/src/components/landing/QuickStart.tsx#L201-L221)
distinguishes temporary staging from the install directory. It says the scripts
verify the selected archive's adjacent checksum, two-binary shape, and versions
before promotion. Configure a managed passphrase before `phantom init` for the
Linux encrypted-file path, and keep it out of agent process inheritance.

## Shared numbered steps

The [step definitions](../apps/web/src/components/landing/QuickStart.tsx#L15-L28)
and [numbered rendering](../apps/web/src/components/landing/QuickStart.tsx#L224-L241)
apply after every platform command:

1. **Verify both binaries:** run `phantom --version` and `phantom-mcp --version`
   on PATH and confirm the pinned public version. These are separate from the
   installed-path version checks already in the platform command.
2. **Protect one supported project:** from an owned Git repository, keep an
   independent provider recovery copy, start with a supported HTTP API key
   rather than a database connection string, and run `phantom init`.

The page labels its receipts illustrative; vault backends and local findings
vary. Keep actual secret values and managed mappings out of agent context and
public output. For more detail, see the [reading guide](quickstart-reading-guide.md)
and [platform comparison](quickstart-platform-comparison.md).
