# Landing-page quickstart staging lifecycle

This traces the copyable command blocks in
[`QuickStart.tsx`](../apps/web/src/components/landing/QuickStart.tsx). Selecting
or copying a command does not create anything; these effects occur when it is
run. The downloaded script's staging is distinct from the install destination
and from any staging performed inside the installer.

## macOS

The install block runs in a Bash subshell with `set -euo pipefail` and
`umask 077`. `mktemp -d` creates a unique `phantom-install.XXXXXX` directory
under `TMPDIR`, or `/tmp` when `TMPDIR` is unset or empty. The quoted path
supports spaces; an unusable nonempty `TMPDIR` is not retried under `/tmp`.
The block assigns `install.sh` inside the directory and installs an `EXIT`
trap before `curl` downloads it. It checks the pinned script digest with
`shasum -a 256 -c -`, runs the script, then checks both installed binaries.

On subshell exit, including a failure after trap installation, the trap attempts
`rm -f` on the script, followed, if reached, by `rmdir` on the empty directory.
The `rmdir` error is suppressed. There is no recursive removal or cleanup
success receipt in the component. Failure or interruption between directory
creation and trap installation, termination that prevents the trap from
running, filesystem errors, or extra contents can leave artifacts. Cleanup
does not remove the installed binaries.

## Linux

The install block uses the same subshell, private umask, directory template,
parent selection, script path, and exit trap as macOS. It downloads the script
after installing the trap and verifies the pinned digest with `sha256sum -c -`
before running it and checking both binaries. The same best-effort removal,
missing recursive cleanup and success receipt, and failure limits apply.

## Windows

The PowerShell install block constructs a GUID-based
`phantom-install-<release>-<guid>.ps1` path under `$env:TEMP`; assignment
creates neither a directory nor a file. Inside `try`, `Invoke-WebRequest`
downloads the script to that path. `Get-FileHash` checks its pinned digest
before execution and the block checks both installed executables. `finally`
attempts to remove the file with `Remove-Item`, suppressing removal errors.
The component creates no staging directory here, has no fallback for
`$env:TEMP`, and does not remove that parent directory or report successful
cleanup. Interruption that prevents `finally` or a removal failure can leave
the file behind.

## Later command blocks and scope

The displayed `phantom --version` / `phantom-mcp --version` block and
`phantom init` block have no explicit staging directory or cleanup in the
component. This does not rule out internal temporary files in the programs;
`phantom init` is a separate project and vault operation. Similarly, the
installers manage their own archive staging and recovery; see
[installer staging](installer-staging.md) and the source linked by each card.
Before removing a suspected leftover, verify that it belongs to a finished run
and is not in use by another installation.
