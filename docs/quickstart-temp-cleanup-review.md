# Landing-page quickstart: temporary staging cleanup review

This review covers the three platform commands displayed by
[`QuickStart.tsx`](../apps/web/src/components/landing/QuickStart.tsx). Use the
panel for the current command and inspect its linked pinned installer source
before running it. The temporary installer described here is separate from the
installer's own archive staging and from the installed binaries.

## macOS

1. The Bash subshell enables error handling and sets `umask 077`. `mktemp -d`
   creates a unique `phantom-install.XXXXXX` directory under `TMPDIR`, or
   `/tmp` when `TMPDIR` is unset or empty. The command assigns `install.sh`
   within it, installs an `EXIT` trap, then downloads the script there.
2. After checking its pinned digest with `shasum -a 256 -c -`, the command
   runs the installer and checks both installed binaries. On subshell exit,
   including a failure after the trap is installed, the trap attempts `rm -f`
   on the installer and, if execution reaches the next command, `rmdir` on
   the staging directory. `rmdir` removes only an empty directory; its error
   is suppressed.

## Windows

1. The PowerShell block sets `$ErrorActionPreference` to `Stop` and constructs
   a GUID-based `phantom-install-<release>-<guid>.ps1` path under `$env:TEMP`.
   This assignment does not create a directory or file; `Invoke-WebRequest`
   writes the downloaded installer at that path inside the `try` block.
2. The block checks the pinned digest with `Get-FileHash`, runs the installer,
   and checks both installed executables. Its `finally` block attempts
   `Remove-Item -LiteralPath $Installer -Force -ErrorAction SilentlyContinue`,
   including when an error occurs inside `try`. Removal errors are suppressed.

## Linux

1. As on macOS, the Bash subshell sets `umask 077` and uses `mktemp -d` to
   create a unique `phantom-install.XXXXXX` directory under `TMPDIR`, or
   `/tmp` when unset or empty. It assigns `install.sh` inside it, installs an
   `EXIT` trap, and downloads the script there.
2. After checking its pinned digest with `sha256sum -c -`, the command runs
   the installer and checks both installed binaries. On subshell exit,
   including a failure after trap installation, the trap attempts `rm -f` on
   the installer followed, if execution reaches it, by `rmdir` on the empty
   staging directory; the directory removal error is suppressed.

## Review limits and leftovers

Cleanup is best effort, not a guarantee. On Unix, a failure or interruption
between directory creation and trap installation, an uncatchable termination,
filesystem errors, or extra directory contents can leave artifacts. On Windows,
an error before `try`, an interruption that prevents `finally` from running,
or a removal error can
leave the file. These commands do not report a successful cleanup receipt.
Inspect any suspected leftovers and confirm they belong to a finished run
before removing them; do not remove another active installation's files.

The panel's cleanup does not remove the user-owned installation or undo a
successful install. The invoked installers manage their own archive staging,
promotion, and recovery; see [Unix installer staging](installer-staging.md)
for its separate cleanup and recovery limits and the linked installer source
for platform-specific details. The later PATH-based version checks create no
staging here; `phantom init` is a separate project and vault operation, not
part of this temporary installer cleanup.
