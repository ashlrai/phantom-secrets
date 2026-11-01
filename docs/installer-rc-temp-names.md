# Unix installer RC temporary names

The checked-in [`scripts/install.sh`](../scripts/install.sh#L305-L320) creates
two temporary siblings when it needs to add the installed directory to `PATH`:

| Variable | `mktemp` template | Purpose |
| --- | --- | --- |
| `before_tmp` | `$rc_parent/.phantom-path.before.XXXXXX` | Snapshot for checking the marker and detecting changes to an existing startup file. |
| `candidate_tmp` | `$rc_parent/.phantom-path.candidate.XXXXXX` | Proposed startup file, including the new PATH entry, before replacement. |

`rc_parent` is the physical path of the selected startup file's parent directory,
created if necessary and resolved with `cd` and `pwd -P`. The basename of
`SHELL` selects `$HOME/.zshrc` for zsh, `$HOME/.config/fish/config.fish` for
fish, and `$HOME/.bashrc` otherwise. `mktemp` replaces the `XXXXXX` suffix;
these files are siblings of the startup file, not children of `TMPDIR` or the
binary staging directory. PATH setup is attempted only if the install directory
is absent from the current `PATH`.

Both files can contain shell configuration. The script attempts cleanup on
handled failures, removes the snapshot after moving the candidate, and does
not guarantee cleanup after interruption or filesystem errors. Inspect any
leftovers and the startup file before removing them, and avoid disturbing an
active installer. See the [PATH update flow](installer-path-update-flow.md)
for checks, replacement, and cleanup details. This reference describes the
repository script, not necessarily an installed or deployed copy.
