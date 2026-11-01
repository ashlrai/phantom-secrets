# Public Unix installer staging directory

The checked-in [public Bash installer](../apps/web/public/install.sh) creates a
private staging directory beside the installation destination, using this
`mktemp` template:

```text
<install_parent>/.<install_name>.install.XXXXXX
```

The exact command is `mktemp -d "$install_parent/.${install_name}.install.XXXXXX"`;
`mktemp` replaces the six `X` characters with a unique suffix, and the resulting
path is stored in `stage_root`. The installer acquires its sibling installation
lock first. See [stage creation](../apps/web/public/install.sh#L435-L443).

The destination defaults to `$HOME/.phantom-secrets/bin`. An explicitly set
`PHANTOM_INSTALL_DIR` must be a nonempty absolute path containing only the
allowed characters. The installer obtains `install_parent` with `dirname` and
`install_name` with `basename`, creates the parent if necessary, and resolves
the parent to its physical path with `pwd -P`. Thus the stage is under that
resolved parent, not inside the destination; setting `TMPDIR` does not select
its location. See [destination selection](../apps/web/public/install.sh#L23),
[override validation](../apps/web/public/install.sh#L58-L66), and
[parent resolution](../apps/web/public/install.sh#L425-L433).

For example, the default template is
`$HOME/.phantom-secrets/.bin.install.XXXXXX`, with the parent replaced by its
physical path. A destination of `/opt/phantom/tools` produces
`/opt/phantom/.tools.install.XXXXXX` when the parent resolves to `/opt/phantom`.
The stage and its `download` and `candidate` children are set to mode 700;
they hold the release files and candidate installation before promotion. The
exit trap attempts to remove the stage, but an uncatchable termination or a
filesystem error can leave it behind. See [staging](../apps/web/public/install.sh#L437-L455),
[promotion](../apps/web/public/install.sh#L498-L522), and
[cleanup](../apps/web/public/install.sh#L119-L139).

This stage is separate from the landing page's temporary downloaded script;
see [installer temporary locations](installer-temp-environment.md). This page
describes the checked-in public Unix script, not the PowerShell installer or a
potentially different deployed revision.
