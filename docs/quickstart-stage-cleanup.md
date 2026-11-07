# Quickstart installer staging and cleanup

The copyable install commands in [`QuickStart.tsx`](../apps/web/src/components/landing/QuickStart.tsx)
use temporary space for the downloaded installer script. Selecting or copying a
command creates nothing; the following describes running it. The staging area
is separate from the installed binaries and from the installer's own archive
staging. Review the panel's pinned installer source before running it.

## macOS

The Bash subshell sets `umask 077`, then creates a unique directory with:

```sh
phantom_stage="$(mktemp -d "${TMPDIR:-/tmp}/phantom-install.XXXXXX")"
```

The parent is `TMPDIR`, or `/tmp` if `TMPDIR` is unset or empty. A nonempty
`TMPDIR` must be usable; there is no retry in `/tmp` if creation fails. Quoting
allows spaces in the path. The command assigns `install.sh` in that directory,
installs an `EXIT` trap, downloads the script, verifies it with
`shasum -a 256 -c -`, and runs it before checking both installed binaries.

On subshell exit, including failures after the trap is installed, the trap
attempts to remove the script with `rm -f` and then the empty directory with
`rmdir`. Directory removal errors are suppressed. Cleanup is best effort:
interruption before trap installation, termination that prevents the trap from
running, filesystem errors, or extra directory contents can leave artifacts.

## Windows

The PowerShell block constructs a GUID-based `phantom-install-<release>-<guid>.ps1`
file path under `$env:TEMP`; assigning the path creates neither a directory nor
a file. The displayed command creates no staging directory and specifies no
fallback for `$env:TEMP`. Inside `try`, `Invoke-WebRequest` downloads the file,
`Get-FileHash` verifies it, and the installer runs before both installed
executables are checked.

The `finally` block attempts to remove the installer file with `Remove-Item`,
including after errors inside `try`. Removal errors are suppressed. An error
before `try`, interruption that prevents `finally` from running, or a removal
error can leave the file behind.

## Linux

The Bash subshell uses the same `umask 077`, `mktemp -d` assignment, `TMPDIR`
selection and `/tmp` fallback as macOS, and stages `install.sh` in the new
unique directory. It installs the same `EXIT` trap before downloading, then
verifies the script with `sha256sum -c -` before running it and checking both
installed binaries. The same best-effort cleanup and limits described for
macOS apply.

Cleanup does not uninstall Phantom. Inspect suspected leftovers and confirm
they belong to a finished run before removing them; another installation may
still be using its staging files. See the [cleanup review](quickstart-temp-cleanup-review.md)
and [Unix installer staging guide](installer-staging.md) for further details.
