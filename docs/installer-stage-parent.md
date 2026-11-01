# Unix installer stage parent

This page describes the repository's [Bash installer](../scripts/install.sh),
not the PowerShell installer or the temporary script downloaded by the landing
page. The installer creates its release staging directory as a sibling of the
installation destination:

```text
<install_parent>/.<install_name>.install.XXXXXX
```

The actual command is `mktemp -d "$install_parent/.${install_name}.install.XXXXXX"`;
`XXXXXX` is the template replaced by `mktemp` with a unique suffix. The path
returned by `mktemp` is stored in `stage_root`. See
[stage creation](../scripts/install.sh#L437-L443).

`INSTALL_DIR` defaults to `$HOME/.phantom-secrets/bin` and can be set with
`PHANTOM_INSTALL_DIR`. An explicitly supplied override must be a nonempty
absolute path with restricted characters. The installer derives `install_parent`
with `dirname` and `install_name` with `basename`, creates the parent if needed,
and resolves that parent to its physical path (`pwd -P`) before acquiring the
lock and creating the stage. The stage is therefore under `install_parent`,
not inside `INSTALL_DIR` and not under `TMPDIR` merely because `TMPDIR` is set.
See [destination selection](../scripts/install.sh#L23),
[override validation](../scripts/install.sh#L58-L66), and
[parent resolution](../scripts/install.sh#L425-L435).

For the default destination, the template is
`$HOME/.phantom-secrets/.bin.install.XXXXXX`, using the parent's resolved
physical path. A custom destination such as `/opt/phantom/tools` yields
`/opt/phantom/.tools.install.XXXXXX` if its parent resolves to `/opt/phantom`.
The installer sets the stage and its `download` and `candidate` children to
mode 700. Its exit trap attempts to remove the stage; abrupt termination or
filesystem errors can leave it behind. See [cleanup](../scripts/install.sh#L119-L139)
and the [staging review](installer-staging-review.md) for rollback and recovery
limits.
