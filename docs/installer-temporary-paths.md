# Unix installer temporary paths

The [repository installer](../scripts/install.sh) and [web-served installer](../apps/web/public/install.sh) use the same temporary path templates described below. `XXXXXX` is replaced by `mktemp`; these are templates, not literal filenames. The installers have other differences, so consult each script for its complete behavior.

## Release staging

The installation directory defaults to `$HOME/.phantom-secrets/bin`; `PHANTOM_INSTALL_DIR` can select another absolute path subject to the installer's character restrictions. The installer creates its parent and resolves it physically (`pwd -P`), then acquires an install lock and creates:

```text
<resolved install parent>/.<install directory name>.install.XXXXXX/
```

For the default directory, this is `$HOME/.phantom-secrets/.bin.install.XXXXXX/` when the parent has no symlinks. The `download/` child holds the archive and checksum; `candidate/` holds the extracted binaries and install receipt before promotion. The stage and its children are mode 700. The template is under the install parent, not `TMPDIR`.

The exit trap attempts to remove the staging tree on success and ordinary failure, including HUP, INT, and TERM. It also attempts rollback when necessary and the installer still owns the lock. An uncatchable termination or filesystem error can leave artifacts; do not disturb an active installer. See the [staging directory reference](installer-staging-directory-reference.md) for details.

## Shell PATH update

Only when the install directory is absent from the current `PATH`, the installer selects `~/.zshrc` for zsh, `~/.config/fish/config.fish` for fish, or `~/.bashrc` otherwise, based on the basename of `SHELL`. It creates and physically resolves the startup file's parent, then creates two temporary siblings there:

| Template | Purpose |
| --- | --- |
| `.phantom-path.before.XXXXXX` | Snapshot for the marker and pre-replacement checks; empty if the startup file was absent. |
| `.phantom-path.candidate.XXXXXX` | Proposed startup file, including the PATH addition. |

These are separate from release staging and do not use `TMPDIR` as their parent. Existing startup-file attributes can be preserved by `cp -p`, and both files can contain shell configuration. The function attempts to remove them on handled failures or when the marker already exists; on success it moves the candidate over the startup file and removes the snapshot. The exit trap does not clean these siblings, and interruption or filesystem errors can leave them behind. Inspect leftovers and the startup file before cleanup. A PATH update failure warns but does not undo the binary installation. See the [PATH update reference](installer-path-update-reference.md) for the checks and recovery limits.
