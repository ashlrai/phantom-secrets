# Installer temporary locations and environment

This describes the checked-in [landing-page commands](../apps/web/src/components/landing/QuickStart.tsx)
and the Unix [repository installer](../scripts/install.sh). The landing page
downloads a script from a pinned source commit, so compare that version before
assuming it has the same behavior as the current repository installer. The
Windows row below covers the landing command only, not `install.ps1` internals.

## Landing command: downloaded script

| Platform | Temporary location and source | Cleanup |
| --- | --- | --- |
| macOS, Linux | `mktemp -d` creates `phantom-install.XXXXXX` under `${TMPDIR:-/tmp}`; unset or empty `TMPDIR` selects `/tmp`. The downloaded script is `install.sh` inside that directory. The quoted template accommodates spaces. See [macOS](../apps/web/src/components/landing/QuickStart.tsx#L46-L58) and [Linux](../apps/web/src/components/landing/QuickStart.tsx#L107-L119). | After the EXIT trap is installed, it attempts to remove the script and then the empty directory on exit, including failures. Cleanup is best effort; termination before trap installation, an uncatchable signal, or filesystem errors can leave files. |
| Windows | `Join-Path` combines `$env:TEMP` with `phantom-install-<release>-<GUID>.ps1`; the release tag and a new GUID form the filename. See the [Windows command](../apps/web/src/components/landing/QuickStart.tsx#L74-L92). | Its `finally` block attempts to remove the file and suppresses removal errors; abrupt termination can leave it behind. |

The Unix command sets `umask 077` and runs in a subshell. Its temporary
directory holds the installer script, not the release archive or installed
binaries. The command then runs the installer, which has its own staging paths
below. The displayed Unix version checks use `$HOME/.phantom-secrets/bin`
even if `PHANTOM_INSTALL_DIR` changes the actual destination; check both
binaries at the custom destination in that case. See the linked commands above
and [install destination selection](../scripts/install.sh#L23).

## Unix installer: installation and PATH paths

`INSTALL_DIR` defaults to `$HOME/.phantom-secrets/bin`; a nonempty, absolute,
restricted-character `PHANTOM_INSTALL_DIR` overrides it. An explicitly empty
override is rejected. The installer creates and resolves the parent to its
physical path, then derives the installation name from the destination basename.
See [selection](../scripts/install.sh#L23), [override validation](../scripts/install.sh#L58-L66),
and [parent resolution](../scripts/install.sh#L408-L435).

| Temporary location | Derived from and purpose | Source |
| --- | --- | --- |
| `<install-parent>/.<install-name>.install.XXXXXX` | A private `mktemp` staging directory beside the destination. Its `download` holds the archive and checksum; `candidate` holds the extracted binaries and receipt before promotion. These explicit paths use the install parent, not `TMPDIR`. | [Staging and downloads](../scripts/install.sh#L437-L457), [extraction and receipt](../scripts/install.sh#L485-L498) |
| `<install-parent>/.<install-name>.backup.<stage-suffix>` | Sibling backup of the previous installation during promotion; the suffix comes from the staging directory. After successful validation it is moved into the stage as `previous-live`. On a failed promotion, `failed-live` may also be placed in the stage during rollback. | [Promotion](../scripts/install.sh#L501-L525), [rollback](../scripts/install.sh#L119-L130) |
| `<install-parent>/.<install-name>.install.lock`, with `owner` | Sibling coordination directory and owner file. A stale lock may be renamed to `.<install-name>.install.lock.stale.<lock-token>` in the same parent and removed. | [Lock acquisition and stale handling](../scripts/install.sh#L218-L303) |
| `<rc-parent>/.phantom-path.before.XXXXXX` and `<rc-parent>/.phantom-path.candidate.XXXXXX` | If the installed directory is absent from `PATH`, the installer selects a startup file from `$HOME` and the basename of `$SHELL`: `.zshrc` for zsh, `.config/fish/config.fish` for fish, otherwise `.bashrc`. It resolves the startup file's parent physically and creates a snapshot and proposed replacement there. Existing-file copies preserve attributes and may contain the user's shell configuration. | [Selection and temporary files](../scripts/install.sh#L305-L350), [PATH condition](../scripts/install.sh#L529-L531) |

The installer sets `umask 077` and makes the stage and its two subdirectories
mode 700. Its EXIT trap attempts rollback on failure only while it still owns
the lock, removes the stage, and releases its own lock; HUP, INT, and TERM
exit through that trap. A cleanup error can interrupt later cleanup, and an
uncatchable termination, lost ownership, or filesystem failure can leave a
stage, backup, or lock. PATH-file cleanup is separate; interruption can leave
those files too. Inspect leftovers and the live installation before recovery,
and do not remove an active installer's lock. See [cleanup](../scripts/install.sh#L90-L139),
[PATH replacement](../scripts/install.sh#L373-L402), and the detailed
[staging](installer-staging.md) and [PATH](installer-path-review.md) reviews.
