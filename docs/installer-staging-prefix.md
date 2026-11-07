# Unix installer staging prefix

The repository's [Bash installer](../scripts/install.sh) creates a temporary
staging directory beside the installation destination. Its `mktemp` template is:

```text
<install_parent>/.<install_name>.install.XXXXXX
```

The leading dot, `.install.`, and six `X` characters are literal parts of the
template; `mktemp -d` replaces the final six `X` characters to create a unique
directory. The resulting path is stored in `stage_root`. For example, a
destination `/opt/phantom/tools` gives the template
`/opt/phantom/.tools.install.XXXXXX` when `/opt/phantom` is its physical parent.
The actual directory has a generated suffix in place of `XXXXXX`.

The installer defaults to `$HOME/.phantom-secrets/bin`; an explicitly supplied
`PHANTOM_INSTALL_DIR` must be a nonempty absolute path with restricted
characters. It takes `install_parent` from `dirname` and `install_name` from
`basename` of the selected destination, creates the parent if necessary, then
resolves the parent with `pwd -P`. Thus the default template is
`<physical-install-parent>/.bin.install.XXXXXX`, where the complete parent
`$HOME/.phantom-secrets` has been physically resolved. For example, without
symlinks, home `/home/alex` yields `/home/alex/.phantom-secrets/.bin.install.XXXXXX`.
A symlink in the parent path can change the displayed parent. The stage is a sibling of the
destination, not a child of it, and the explicit template does not select
`TMPDIR` as its parent. See [destination selection and staging](../scripts/install.sh#L408-L443).

The stage and its `download` and `candidate` directories are private (mode
700). The installer uses the stage for the download and candidate, and its exit
trap attempts to remove it. An uncatchable termination or filesystem failure
can leave it behind. The separate backup and lock also use the install name;
see [staging and cleanup](installer-staging.md) for promotion, rollback, and
recovery limits. This page describes the repository script, not the separate
temporary script used by the landing-page command or the PowerShell installer.
