# Landing-page quickstart command sequence

This guide explains the commands displayed by the [install panel](https://phm.dev/#install)
in [`QuickStart.tsx`](../apps/web/src/components/landing/QuickStart.tsx). Select
one operating system and use its panel for the current copyable command. Review
its linked pinned installer source and the [full installation guide](getting-started.md#exact-github-assets-macos-linux-and-windows) before running it.
The release tag, source commit, and script digests come from
[`public-release.ts`](../apps/web/src/lib/public-release.ts).

## macOS and Linux

1. A subshell enables error checks and sets a restrictive `umask 077`. It
   creates a unique temporary directory with `mktemp -d` under `TMPDIR`, or
   `/tmp` when that variable is unset or empty. It assigns an `install.sh`
   path inside the directory; this staging directory is not the install directory.
2. An `EXIT` trap is installed before the download. It is intended to clean
   up the temporary script and directory when the subshell exits.
3. The command downloads the pinned installer over HTTPS and checks its fixed
   SHA-256 digest: macOS uses `shasum -a 256 -c -`, while Linux uses
   `sha256sum -c -`. A failed check stops execution before the installer runs.
4. The verified script runs. It selects an archive and checks its adjacent
   checksum, two-binary shape, and versions before promotion into the
   user-owned install directory. The panel then checks both installed binaries
   by their explicit paths.
5. On subshell exit, including failures after trap installation, the trap
   attempts to remove the script and then, if reached, the empty staging
   directory. Cleanup is best effort, not guaranteed: an interruption before
   trap installation or a removal failure can leave artifacts. It does not
   remove the installed binaries.

## Windows

1. The PowerShell block sets errors to stop execution and assigns a unique
   installer file path under `$env:TEMP`. Assigning the path creates neither a
   file nor a Unix-style staging directory.
2. Inside `try`, the block downloads the pinned installer to that path and
   compares its SHA-256 digest using `Get-FileHash`. A mismatch stops execution
   before the installer runs.
3. The verified script runs, selects an archive, and checks its adjacent
   checksum, two-binary shape, and versions before promotion into the
   user-owned install directory. The block checks both installed executables
   by their explicit paths, with failure checks after each invocation.
4. The `finally` block attempts to remove the temporary installer file, even
   after an error inside `try`. Removal errors are suppressed, so cleanup is
   not guaranteed; it does not remove the installed binaries.

## After the platform command

The page next shows `phantom --version` and `phantom-mcp --version` as separate
PATH-based checks of both binaries, then `phantom init` to protect one supported
project. Start from an owned Git repository with an independent provider recovery
copy and a supported HTTP API key. The displayed receipts are illustrative;
local results and vault backends vary. Keep secret values and managed mappings
out of agent context and public output.

The panel's temporary installer cleanup is separate from the installer's own
archive staging and recovery. See the [cleanup review](quickstart-temp-cleanup-review.md)
and [Unix installer staging guide](installer-staging.md) for their limits.
