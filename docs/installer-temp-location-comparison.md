# Quickstart and Unix installer temporary locations

The macOS and Linux commands in [QuickStart.tsx](../apps/web/src/components/landing/QuickStart.tsx)
download and run a pinned installer script. That script then stages the release
for installation. These are **two separate directories**, with separate owners,
contents, location inputs, and cleanup. This comparison uses the checked-in
[Unix installer](../scripts/install.sh); the landing command downloads from a
fixed source commit, so check that pinned version before assuming the current
repository script is identical. Windows uses a temporary PowerShell installer
file; this comparison does not describe `install.ps1` internals.

| | Quickstart download staging | Unix installation staging |
| --- | --- | --- |
| Created by | The macOS or Linux command, in a subshell, before running the installer. | `install.sh`, after resolving the destination parent and acquiring its install lock. |
| Location | `${TMPDIR:-/tmp}/phantom-install.XXXXXX`; unset or empty `TMPDIR` uses `/tmp`. The quoted template permits spaces. | `<install-parent>/.<install-name>.install.XXXXXX`, a sibling of the destination. The explicit parent is derived from `PHANTOM_INSTALL_DIR`, not `TMPDIR`. |
| Contents | The downloaded `install.sh`, verified against the pinned script digest before execution. | `download/` holds the release archive and SHA-256 sidecar; `candidate/` holds the extracted binaries and install receipt before promotion. |
| Cleanup | Once installed, the subshell's EXIT trap attempts to remove the script and then its empty directory, including on failure. | The installer's EXIT trap attempts rollback on failure while it owns the lock, removes the stage, and releases its lock. HUP, INT, and TERM exit through that trap. |

The installer defaults to `$HOME/.phantom-secrets/bin`, so its stage is under
the physical `$HOME/.phantom-secrets` parent with a `.bin.install.` prefix.
An explicitly set `PHANTOM_INSTALL_DIR` must be a nonempty absolute path with
the allowed characters; for example, `/opt/phantom/tools` gives a stage under
the physical `/opt/phantom` parent with a `.tools.install.` prefix. The
installer resolves the parent with `pwd -P`. Changing `TMPDIR` affects the
quickstart directory, not this installation stage; changing
`PHANTOM_INSTALL_DIR` affects the installation stage, not the quickstart
directory. The quickstart's final version checks still name the default bin
directory, so check both binaries at the custom destination when overriding it.

Both Unix commands use `umask 077`; the installer also sets its stage and its
two child directories to mode 700. The directories can happen to share a parent
if configured that way, but are independently created and cleaned up. Cleanup
is best effort: termination before the quickstart trap is installed,
uncatchable termination, lost installer lock ownership, or filesystem errors can
leave artifacts. The installer also uses a sibling backup and lock and may use
temporary files beside a shell startup file; inspect leftovers and the live
installation before recovery, and do not remove an active installer's lock.
See [temporary locations and environment](installer-temp-environment.md) for
those paths and the Windows quickstart, and [installer staging](installer-staging.md)
for promotion and rollback details.
