# Unix installer PATH update flow

This describes [`scripts/install.sh`](../scripts/install.sh), not the Windows
installer. After installing and validating the binaries, the script checks for
the install directory as an exact colon-separated entry in the current `PATH`.
If it is already present, it does not edit a startup file. Otherwise it calls
`add_to_user_path`; a failure warns the user to add the directory manually,
but does not undo the installed binaries.

## Choosing and preparing the files

The basename of `SHELL` selects `~/.zshrc` for zsh,
`~/.config/fish/config.fish` for fish, and `~/.bashrc` for all other names
(including the default, bash). The installer creates the parent directory if
needed and resolves it to a physical path. It then creates two files there,
using `mktemp` and the script's `umask 077`:

| Sibling file | Role |
| --- | --- |
| `.phantom-path.before.XXXXXX` | The snapshot used to check the marker and compare the original contents before replacement. |
| `.phantom-path.candidate.XXXXXX` | The proposed replacement, assembled before the startup file is changed. |

For an existing startup file, the script requires a regular, non-symlink file
with exactly one link. It records the file identity, copies the file to the
snapshot with `cp -p`, and verifies the original identity again. If the
snapshot contains the literal marker `# phantom-secrets PATH`, it removes both
temporary files and returns without changing the startup file; it does not
check whether the existing entry points to the current install directory.
Otherwise it copies the snapshot to the candidate with `cp -p`.

For an absent startup file, both temporary files start empty and are set to
mode 600. Existing-file copies use `cp -p`, so their attributes can reflect
the original file. Both siblings can contain startup configuration and should
be handled accordingly. The script appends the marker and a PATH command to
the candidate: `set -gx PATH` for fish or `export PATH` for other shells.

## Replacement and cleanup

Before the move, the script checks that an absent startup file is still
absent. For an existing file, it checks the recorded identity, regular
non-symlink type, and contents against the snapshot. If those checks pass,
it records the candidate's identity, moves the candidate onto the startup
file, removes the snapshot, and verifies the resulting identity, type, and
marker. It does not restore the snapshot if that final verification fails.
The update affects future shells, or the current shell after sourcing the
startup file as suggested by the installer.

On explicitly handled failures before the move, the function attempts to
remove both siblings; if creating the candidate fails, it removes the
already-created snapshot. On success the candidate has been moved and the
snapshot is removed. Cleanup is not guaranteed: interruption, unhandled
failures, or filesystem errors can leave siblings behind. The general exit
trap cleans the binary staging tree and lock, not these PATH siblings. Inspect
leftovers and the startup file before removing anything, and avoid disturbing
an active installer. The PATH candidate is distinct from the binary candidate
and backup described in [installer staging](installer-staging.md).
