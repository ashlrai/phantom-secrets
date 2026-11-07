# Unix installer PATH temporary-file failures

This reference describes the checked-in [`scripts/install.sh`](../scripts/install.sh),
not the Windows installer or a separately published copy. After installing and
validating both binaries, the script checks whether the install directory is an
exact entry in the current `PATH`. Only if it is absent does the installer try
to update a shell startup file. The basename of `SHELL` selects `~/.zshrc` for
zsh, `~/.config/fish/config.fish` for fish, or `~/.bashrc` otherwise. The
installer creates the parent directory if needed and resolves its physical path.

It then calls `mktemp` twice in that parent, under `umask 077`, before reading
or changing the startup file:

| Failure | Immediate behavior |
| --- | --- |
| `.phantom-path.before.XXXXXX` (snapshot) creation fails | The function returns failure immediately; it does not attempt to create the candidate. |
| `.phantom-path.candidate.XXXXXX` (proposed replacement) creation fails | The function attempts to remove the already-created snapshot with `rm -f`, then returns failure. |

In either case the installer has not copied, created, or replaced the startup
file. A parent directory created earlier can remain. The `mktemp` command may
print its own diagnostic; the caller also warns `could not update your shell
PATH; add <install-directory> manually`. The already validated installation is
not rolled back, the completion messages are printed, and the installer exits
successfully if its remaining commands succeed. A successful exit alone does
not mean PATH setup succeeded.

Cleanup is best effort: a failed removal, interruption, or filesystem error
can leave a temporary file. The installer's general exit trap does not clean
these PATH siblings. Inspect the selected startup file and any leftovers before
removing them, without disturbing an active installer. Startup files and
temporary copies can contain private configuration. After resolving the
filesystem issue, add the installation directory to PATH manually or rerun the
installer, then open a new shell or source the appropriate startup file. See
the [PATH update flow](installer-path-update-flow.md) for later failure modes,
including the different consequences of failure after replacement.
