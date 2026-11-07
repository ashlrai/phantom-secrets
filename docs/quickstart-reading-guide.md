# Reading the landing-page quickstart

This guide follows the [landing-page install panel](https://phm.dev/#install)
in `apps/web/src/components/landing/QuickStart.tsx`. Choose the card for your
operating system; macOS is selected initially. Each card links to the pinned
installer source, architecture-specific release archives, and their SHA-256
sidecars. Review the source and the [full installation guide](getting-started.md#exact-github-assets-macos-linux-and-windows)
before running a command. The panels use the pinned release and source commit
defined in `apps/web/src/lib/public-release.ts`; use the page for the current
copyable commands rather than copying a potentially stale command from this guide.

## macOS

1. The command starts a subshell, enables failure checks, sets a restrictive
   `umask`, and creates a temporary `phantom-install.XXXXXX` directory with
   `mktemp -d` under `TMPDIR`, or `/tmp` if `TMPDIR` is unset or empty. It
   assigns `install.sh` inside that directory and installs an exit trap.
2. It downloads the installer from the pinned source commit over HTTPS, then
   checks the script's fixed SHA-256 digest with `shasum -a 256 -c -`.
3. Only after that check succeeds, it runs the script with `bash`. The script
   selects Apple Silicon or Intel, checks the archive's adjacent checksum, its
   two-binary shape, and versions before promoting the binaries to the
   user-owned install directory.
4. It runs `phantom --version` and `phantom-mcp --version` from
   `~/.phantom-secrets/bin`. On subshell exit, including after a failure once
   the trap is installed, the trap attempts to remove the script and then the
   empty staging directory. Cleanup can fail and is not guaranteed. The staging
   directory is temporary and is not the install directory.

Keychain is used when available. The release is not notarized; inspect the
pinned script and verify its checksum before any policy-dependent unblock.

## Windows

1. The PowerShell block stops on errors and assigns a unique temporary
   installer file under `$env:TEMP`; it does not create the Unix staging
   directory described above.
2. It downloads the pinned `install.ps1` and compares its SHA-256 digest with
   the fixed expected digest using `Get-FileHash`. A mismatch stops the block.
3. It runs the verified installer, which selects ARM64 or x64 and checks the
   archive's adjacent checksum, two-binary shape, and versions before
   promoting the binaries to the user-owned install directory.
4. It checks both installed executables' versions under
   `$env:USERPROFILE\.phantom-secrets\bin`. A `finally` block attempts to remove
   the temporary installer file, including on failure; removal is not guaranteed.

Current-user Credential Manager is used when available. Windows archives are
not Authenticode-signed; unblock only after checksum verification and when local
policy permits it.

## Linux

1. The command starts a subshell, enables failure checks, sets a restrictive
   `umask`, and creates a temporary `phantom-install.XXXXXX` directory with
   `mktemp -d` under `TMPDIR`, or `/tmp` if `TMPDIR` is unset or empty. It
   assigns `install.sh` inside that directory and installs an exit trap.
2. It downloads the installer from the pinned source commit over HTTPS, then
   checks the script's fixed SHA-256 digest with `sha256sum -c -`.
3. Only after that check succeeds, it runs the script with `bash`. The script
   checks the selected archive's adjacent checksum, two-binary shape, and
   versions before promoting the binaries to the user-owned install directory.
4. It runs `phantom --version` and `phantom-mcp --version` from
   `~/.phantom-secrets/bin`. On subshell exit, including after a failure once
   the trap is installed, the trap attempts to remove the script and then the
   empty staging directory. Cleanup can fail and is not guaranteed. The staging
   directory is temporary and is not the install directory.

The published GNU targets enforce a glibc 2.35 symbol ceiling; musl and Alpine
are not published. The initial keyutils vault is session-persistent, not
reboot-persistent. Desktop users can migrate to Secret Service; headless
environments need a managed passphrase for the encrypted-file backend. Set it
before `phantom init` and keep it out of agent process inheritance.

## After the platform command

1. **Verify both binaries.** The page next shows `phantom --version` and
   `phantom-mcp --version` to confirm both report the pinned public version.
   This is a separate, PATH-based check after the platform command's explicit
   installed-path checks.
2. **Protect one supported project.** From an owned Git repository, keep an
   independent provider recovery copy and start with a supported HTTP API key,
   not a database connection string. Run `phantom init` to store detected values
   in the vault and rewrite the managed dotenv. Keep actual values and managed
   mappings out of agent context and public output.

The receipts shown on the page are illustrative: local findings and vault
backends vary. Release artifact evidence does not establish every local shell,
policy, or credential-store state. See [getting started](getting-started.md)
for the complete workflow and manual archive installation.
