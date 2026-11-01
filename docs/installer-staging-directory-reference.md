# Repository installer staging directory reference

This reference describes [`scripts/install.sh`](../scripts/install.sh), the Unix
repository installer. Its release staging directory is a sibling of the selected
installation directory, with this template:

```text
<install_parent>/.<install_name>.install.XXXXXX
```

The installer selects `$HOME/.phantom-secrets/bin` by default, or the value of
`PHANTOM_INSTALL_DIR` when supplied. An explicit override must be a nonempty
absolute path using the script's restricted character set. It derives
`install_parent` with `dirname` and `install_name` with `basename`, creates the
parent if necessary, and resolves that parent physically with `pwd -P`. Thus a
symlink in the parent path can change the resulting path. After acquiring the
installation lock, it runs:

```bash
mktemp -d "$install_parent/.${install_name}.install.XXXXXX"
```

`mktemp` replaces the six trailing `X` characters with a generated suffix and
returns the created path in `stage_root`. The leading dot, installation name,
and `.install.` are the fixed parts of the directory name. For example:

| Selected installation directory | Staging template (assuming the parent has no symlinks) |
| --- | --- |
| `$HOME/.phantom-secrets/bin` | `$HOME/.phantom-secrets/.bin.install.XXXXXX` |
| `/opt/phantom/tools` | `/opt/phantom/.tools.install.XXXXXX` |

The explicit template puts the stage in the resolved installation parent; it
does not use `TMPDIR` as the staging parent. The installer sets `stage_root` and
its `download` and `candidate` children to mode 700. Downloads and the checked
candidate stay there until promotion. The exit trap attempts to remove the
stage on success and ordinary failure, including HUP, INT, and TERM; an
uncatchable termination or filesystem error can leave it behind. See the
[creation and promotion code](../scripts/install.sh#L425-L525),
[cleanup code](../scripts/install.sh#L119-L139), and
[staging review](installer-staging-review.md) for rollback and recovery limits.
This directory is distinct from the landing-page command's temporary script
directory and from the Windows installer.
