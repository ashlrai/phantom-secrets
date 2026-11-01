# Unix installer staging prefixes

Two checked-in Bash installers stage releases the same way:
[`scripts/install.sh`](../scripts/install.sh) is the repository installer and
[`apps/web/public/install.sh`](../apps/web/public/install.sh) is the web-served
copy. This page compares repository files, not a deployed website; the
PowerShell installers are out of scope. Each script creates its temporary
staging directory beside the installation destination with the identical
`mktemp` template:

```text
<install_parent>/.<install_name>.install.XXXXXX
```

| Script | Staging prefix | Parent directory |
|--------|----------------|------------------|
| `scripts/install.sh` | `.<install_name>.install.XXXXXX` in `install_parent` | `dirname "$INSTALL_DIR"`, physically resolved |
| `apps/web/public/install.sh` | `.<install_name>.install.XXXXXX` in `install_parent` | `dirname "$INSTALL_DIR"`, physically resolved |

The leading dot, `.install.`, and the six `X` characters are literal template
parts; `mktemp -d` replaces the final `XXXXXX` with a unique suffix, and the
resulting path is stored in `stage_root`. The actual commands are
`mktemp -d "$install_parent/.${install_name}.install.XXXXXX"` in
[repository staging](../scripts/install.sh#L437-L443) and
[web staging](../apps/web/public/install.sh#L437-L441). In the repository
copy each staging step carries an explicit `|| die` diagnosis; the web copy
relies on Bash error exit and the underlying command's diagnostic. The prefix
itself is byte-identical.

## Parent directory

Both scripts derive the parent identically. `INSTALL_DIR` defaults to
`$HOME/.phantom-secrets/bin`; an explicitly supplied `PHANTOM_INSTALL_DIR`
must be a nonempty absolute path with restricted characters. The installer
takes `install_parent` from `dirname` and `install_name` from `basename` of
the selected destination, creates the parent if necessary, then resolves it
with `pwd -P`. See
[repository destination selection](../scripts/install.sh#L425-L435) and
[web destination selection](../apps/web/public/install.sh#L425-L435).

The default template is therefore
`$HOME/.phantom-secrets/.bin.install.XXXXXX`, where `$HOME/.phantom-secrets`
is the physically resolved parent and `bin` is the install name. A custom
destination `/opt/phantom/tools` yields `/opt/phantom/.tools.install.XXXXXX`
when its parent resolves to `/opt/phantom`. A symlink in the parent path can
change the displayed parent. The stage is a sibling of the destination — not
a child of `INSTALL_DIR`, and not under `TMPDIR` merely because `TMPDIR` is
set.

## Sibling prefixes in the same parent

The stage shares `install_parent` and the `.<install_name>` prefix family
with the installer's other private paths in both scripts:

- `.<install_name>.install.lock` — the lock directory acquired before
  staging ([repository](../scripts/install.sh#L217),
  [web](../apps/web/public/install.sh#L217)); a stale contender is renamed
  to `.<install_name>.install.lock.stale.<token>`
  ([repository](../scripts/install.sh#L294),
  [web](../apps/web/public/install.sh#L294)).
- `.<install_name>.backup.<stage-suffix>` — the rollback target for a
  replaced live directory, where the suffix is the stage's generated
  `mktemp` tail ([repository](../scripts/install.sh#L501),
  [web](../apps/web/public/install.sh#L498)).

The stage and its `download` and `candidate` children are mode 700, and the
exit trap attempts to remove the stage; uncatchable termination or
filesystem failure can leave it behind. See
[staging and cleanup](installer-staging.md) for the promotion and rollback
sequence, [staging prefix](installer-staging-prefix.md) for the
repository-only discussion, and
[copy comparison](installer-copy-comparison.md) for how the two checked-in
copies differ.
