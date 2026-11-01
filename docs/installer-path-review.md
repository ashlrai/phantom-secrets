# Unix installer PATH temporary files

This review describes `add_to_user_path` in [`scripts/install.sh`](../scripts/install.sh#L305-L399).
It runs after the binaries have been installed, only when the install directory
is not already a PATH entry. PATH setup is best effort: failure produces a
warning and does not undo the installation.

The selected startup file is `~/.zshrc` for zsh, `~/.config/fish/config.fish`
for fish, and `~/.bashrc` for other shells. The script creates its parent if
needed and resolves that parent to a physical path. In that directory, it
uses `mktemp` to create two sibling files (with `umask 077` in effect):

| Temporary file | Purpose |
| --- | --- |
| `.phantom-path.before.XXXXXX` | Snapshot of an existing startup file, used to find the marker and compare the original contents before replacement. It is empty if the startup file was absent. |
| `.phantom-path.candidate.XXXXXX` | Proposed replacement: a copy of the snapshot plus the marker and shell-specific PATH command, or an initially empty file plus that addition. |

For an existing startup file the script requires a regular, non-symlink file
with one link, records its identity, copies it with `cp -p`, and checks the
identity again. If the snapshot already contains `# phantom-secrets PATH`, it
removes both temporary files and leaves the startup file alone. Otherwise it
copies the snapshot to the candidate. For an absent startup file, both files
are emptied and set to mode 600. Existing-file copies preserve attributes via
`cp -p`; they are not necessarily mode 600. Both files can contain the user's
startup configuration and should be treated accordingly.

Before replacement, the script checks that an absent file is still absent, or
that an existing file has the same identity, remains a regular non-symlink,
and has contents matching the snapshot. It records the candidate's identity,
moves the candidate to the startup-file path, removes the snapshot, and then
checks the final identity, file type, and marker. A failed final check reports
failure but does not restore the prior startup file.

On the explicitly handled failures before the move, the script attempts to
remove both files; if creation of the candidate fails, it removes the already
created snapshot. On success, the candidate has been moved and the snapshot
is removed. Cleanup is not guaranteed: the general exit trap cleans the binary
staging tree and lock, not these PATH siblings, and interruption, an unhandled
command failure, or filesystem errors may leave them behind. Inspect any
leftovers and the startup file before removing them, and avoid interfering
with an active installer. These files are distinct from the binary installer
candidate and backup described in [installer staging](installer-staging.md).
