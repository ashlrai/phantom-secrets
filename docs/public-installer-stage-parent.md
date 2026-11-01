# Public Unix installer stage parent

This describes the checked-in [public Bash installer](../apps/web/public/install.sh),
not the PowerShell installer or a separately downloaded installer at another
revision.

`INSTALL_DIR` defaults to `$HOME/.phantom-secrets/bin`. A nonempty absolute
`PHANTOM_INSTALL_DIR` overrides it, subject to the installer's restricted path
characters; an explicitly empty override is rejected. The installer takes
`dirname` and `basename` of the destination as `install_parent` and
`install_name`, creates the parent, and resolves it with `pwd -P` before
reconstructing `INSTALL_DIR`. It rejects a symlink at the destination itself.
See [destination selection](../apps/web/public/install.sh#L23) and
[parent resolution](../apps/web/public/install.sh#L405-L435).

After acquiring the sibling install lock, it runs
`mktemp -d "$install_parent/.${install_name}.install.XXXXXX"` and stores the
result in `stage_root`. Thus the stage pattern is
`<install-parent>/.<install-name>.install.XXXXXX`: a hidden sibling of the live
destination under the physical `install_parent`, not under `TMPDIR`. For the
default destination the template is
`$HOME/.phantom-secrets/.bin.install.XXXXXX`, with the parent resolved to its
physical path and the final six `X` characters replaced by `mktemp`. The stage
and its `download` and `candidate` subdirectories are set to mode 700. See
[stage creation](../apps/web/public/install.sh#L433-L441).

The archive and checksum are placed in `download`; verified binaries and the
install receipt are prepared in `candidate` before promotion. The EXIT trap
removes the stage on ordinary success or failure and attempts rollback on
failure while the lock is still owned. Cleanup is not guaranteed after an
uncatchable termination, lost lock ownership, or filesystem error; inspect the
live destination and siblings before recovering leftovers, and do not remove
an active installer's lock. See [downloads and promotion](../apps/web/public/install.sh#L443-L522),
[cleanup](../apps/web/public/install.sh#L119-L139), and the broader
[staging review](installer-staging.md).
