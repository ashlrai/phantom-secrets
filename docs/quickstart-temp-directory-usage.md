# Landing-page quickstart temporary directory usage

The copyable commands in [`QuickStart.tsx`](../apps/web/src/components/landing/QuickStart.tsx)
are shown one platform at a time. Selecting a platform, displaying a command,
or copying it does not create a directory. The descriptions below concern
what happens when a user runs a displayed command; use the panel for the
complete command and review its linked pinned installer source first.

## macOS

Each run of the install command starts a subshell, sets `umask 077`, and then
runs `mktemp -d` before downloading anything. It creates a new, unique
`phantom-install.XXXXXX` directory under `TMPDIR`, or `/tmp` if `TMPDIR` is
unset or empty. A nonempty `TMPDIR` must name a usable existing parent; the
command does not retry with `/tmp` if creation fails. Quoting allows spaces in
the parent path.

The command assigns `install.sh` inside that directory, installs an `EXIT`
trap, downloads the pinned installer there, and checks its SHA-256 digest with
`shasum -a 256 -c -` before running it. The directory is staging for the
installer script, not the installation destination. After the installer runs,
the command checks both installed binaries. On subshell exit, including failure
after the trap is installed, the trap attempts to remove the script and then
the empty directory. Cleanup is best effort: interruption before the trap is
installed, termination that prevents it running, removal errors, or extra files
can leave artifacts.

## Windows

The displayed PowerShell install command does not create a temporary directory.
It constructs a GUID-based installer **file path** under the existing
`$env:TEMP`; assigning that path creates neither a directory nor a file.
Inside `try`, `Invoke-WebRequest` downloads the installer to the path. The
command verifies its SHA-256 digest with `Get-FileHash` before running it, then
checks both installed executables. The `finally` block attempts to remove the
file, including after an error inside `try`; removal errors are suppressed, so
cleanup is not guaranteed. The displayed command specifies no fallback for
`$env:TEMP`.

## Linux

Each run of the install command creates its own directory at the same point and
with the same `mktemp -d` template, parent selection, and fallback as macOS.
It also stages `install.sh` there, installs the exit trap before downloading,
and runs the installer only after verifying its digest. Linux uses
`sha256sum -c -` for that check. The subsequent binary checks and best-effort
cleanup have the same scope and limits as on macOS.

## Later commands and scope

The separately displayed `phantom --version` and `phantom-mcp --version`
commands check the binaries on `PATH`; their displayed command lines do not
create a temporary directory. The displayed `phantom init` command starts a
separate project and vault operation, not this installer staging sequence; its
command line does not explicitly create a temporary directory. These statements
about command lines do not rule out internal temporary files or directories
created by the invoked programs. The invoked installers also manage their own
archive staging, separate from the panel's script staging; see the
[cleanup review](quickstart-temp-cleanup-review.md) and
[Unix installer staging guide](installer-staging.md).
