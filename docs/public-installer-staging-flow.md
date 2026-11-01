# Public Unix installer staging flow

This describes the checked-in [public Bash installer](../apps/web/public/install.sh),
not the PowerShell installer or the separate temporary directory used to download
an installer in the [landing-page commands](quickstart-command-sequence.md).

## Location and preparation

The destination defaults to `$HOME/.phantom-secrets/bin`; a valid absolute
`PHANTOM_INSTALL_DIR` can select another destination. The installer creates its
parent, resolves that parent with `pwd -P`, rejects a symlink destination, and
acquires the sibling install lock before creating the stage. It runs:

```bash
stage_root="$(mktemp -d "$install_parent/.${install_name}.install.XXXXXX")"
```

Thus the stage is a fresh, hidden sibling of the live destination in its
physical parent, independent of `TMPDIR`. For the default destination its
pattern is `$HOME/.phantom-secrets/.bin.install.XXXXXX`, with the parent
resolved physically. The installer sets the stage to mode 700 and creates
mode-700 `download` and `candidate` children. See [destination and staging](../apps/web/public/install.sh#L425-L443).

## Validation and promotion

The archive and SHA-256 sidecar are placed in `download`. After checking the
sidecar and digest, the installer requires exactly the two regular archive
members `phantom` and `phantom-mcp`, extracts them into `candidate`, verifies
their versions, and writes a source receipt there. This keeps incomplete or
unverified downloads out of the live install. See [validation](../apps/web/public/install.sh#L445-L496).

With lock ownership checked, an existing live directory is moved to the sibling
`.<install-name>.backup.<stage-suffix>` and `candidate` is moved into place.
After final-path validation, the old installation is moved into the stage as
`previous-live`, to be removed during cleanup. The moves are separate, so the
live path can briefly be absent. See [promotion](../apps/web/public/install.sh#L498-L522).

## Cleanup and its limits

The `EXIT` trap runs on normal exit and failure; HUP, INT, and TERM exit through
it. On a nonzero exit, **only while the lock is still owned**, it attempts to
move a promoted live candidate into the stage as `failed-live` and restore a
backup if the live path is absent. Both rollback moves are best effort. It then
removes the staging tree and releases the lock only if its owner token still
matches. A cleanup filesystem error can interrupt later cleanup. See [cleanup](../apps/web/public/install.sh#L90-L139).

Cleanup is not guaranteed after SIGKILL, a crash, power loss, or filesystem
errors. Lost lock ownership prevents rollback, and a later stale-lock reclaim
does not restore an orphaned backup. Inspect the live destination and sibling
stage, backup, and lock before recovery; do not remove an active installer's
lock. PATH setup happens after promotion and uses separate temporary files;
a PATH update failure warns without rolling back the install. See the
[staging review](public-installer-staging-questions.md) for recovery questions.
