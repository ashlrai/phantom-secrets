# Unix installer PATH update: temporary files

This reference describes the checked-in [repository installer](../scripts/install.sh),
not the web-served or Windows installers. After installation it updates a shell
startup file only when the install directory is not an exact entry in the
current `PATH`. A failed update produces a warning and leaves the installed
binaries in place. See the [call site](../scripts/install.sh#L529-L531).

The basename of `SHELL` selects `~/.zshrc` for zsh,
`~/.config/fish/config.fish` for fish, and `~/.bashrc` otherwise. After creating
and physically resolving that file's parent directory, the installer uses
`mktemp` to create two siblings there, not under the binary staging directory
or necessarily under `TMPDIR`. The `XXXXXX` suffix is replaced by `mktemp`.
See [file selection and creation](../scripts/install.sh#L305-L321).

| Template in the startup file's parent | Purpose |
| --- | --- |
| `.phantom-path.before.XXXXXX` | Snapshot of the existing startup file, used for the marker check and comparison before replacement; empty if the startup file was absent. |
| `.phantom-path.candidate.XXXXXX` | Proposed replacement: the original content when present, followed by the marker and shell-specific PATH command. |

The script starts with `umask 077`, but copies of an existing startup file use
`cp -p` and can retain its attributes. Both files can contain shell configuration;
treat any leftovers accordingly. An absent startup file starts with empty
temporary files explicitly set to mode 600. See [snapshot and candidate
preparation](../scripts/install.sh#L322-L371).

## Cleanup and limits

- If creating the snapshot fails, there is no snapshot to clean up. If creating
  the candidate fails, the function attempts to remove the snapshot.
- If the snapshot already contains `# phantom-secrets PATH`, the function
  attempts to remove both files and returns without replacing the startup file.
  It does not verify that the existing marker refers to the current directory.
- On explicitly handled failures before replacement, the function attempts to
  remove both files. After pre-replacement checks pass, it moves the candidate
  onto the startup file and removes the snapshot. A subsequent identity, type,
  or marker verification failure does not restore the original file. See
  [checks, move, and verification](../scripts/install.sh#L373-L402).

These removals are not guaranteed to succeed. Interruption, unhandled failures,
or filesystem errors can leave files behind. The installer's [exit trap](../scripts/install.sh#L119-L139)
handles the binary staging directory and lock; it does not clean these PATH
siblings. Before removing a leftover, inspect it and the startup file and avoid
disturbing an active installer. For the complete update sequence, see the
[PATH update flow](installer-path-update-flow.md).
