# Unix installer staging and cleanup

This describes the Bash installers in [`scripts/install.sh`](../scripts/install.sh)
and [`apps/web/public/install.sh`](../apps/web/public/install.sh). It does not
cover the PowerShell installers. Both scripts currently pin a reviewed GitHub
release, use the same staging and promotion sequence, and default to
`~/.phantom-secrets/bin`. An absolute, restricted-character
`PHANTOM_INSTALL_DIR` can change that destination. The parent is created and
canonicalized; the destination cannot be the filesystem root or a symlink.
See the [repository installer setup](../scripts/install.sh#L18-L55) and
[destination checks](../scripts/install.sh#L411-L441), and the corresponding
[web setup](../apps/web/public/install.sh#L18-L55) and
[web destination checks](../apps/web/public/install.sh#L411-L441).

## Staging and promotion

1. Before staging, the installer acquires a private sibling lock directory,
   `.<install-name>.install.lock`, with an owner token and heartbeat. A
   contender waits up to the configured deadline and may rename and remove a
   stale lock. Ownership is checked again around promotion. See the
   [repository lock code](../scripts/install.sh#L206-L303) and
   [web lock code](../apps/web/public/install.sh#L206-L303).
2. `mktemp` creates `.<install-name>.install.XXXXXX` in the canonical install
   parent, with mode 700; its `download` and `candidate` subdirectories also
   have mode 700. The archive and its checksum sidecar go into `download`, not
   the live install. Both scripts report explicit errors for staging creation
   and permission failures through the same `|| die` guards. See
   [repository staging](../scripts/install.sh#L443-L449) and
   [web staging](../apps/web/public/install.sh#L443-L449).
3. The installer validates the one-line SHA-256 sidecar and archive digest,
   requires exactly two regular archive members (`phantom` and `phantom-mcp`),
   and extracts into `candidate`. It makes the binaries executable, checks each
   exact `--version` output, and writes a mode-600 source receipt. Both
   copies extract with `tar --no-same-owner`, so a root-run install does
   not keep the release runner's uid on the installed binaries.
   See [repository validation](../scripts/install.sh#L465-L505) and
   [web validation](../apps/web/public/install.sh#L465-L505).
4. Under the lock, an existing install directory is moved to the sibling
   `.<install-name>.backup.<stage-suffix>`, then the candidate is moved into
   place. Both binaries and the receipt are checked again at the final path.
   On success, the previous install is moved into the staging tree as
   `previous-live` for cleanup. Promotion uses separate moves, so readers can
   observe a brief interval without the live directory. See
   [repository promotion](../scripts/install.sh#L507-L533) and
   [web promotion](../apps/web/public/install.sh#L507-L533).

## Cleanup and recovery limits

The `EXIT` trap handles normal exits and failures; HUP, INT, and TERM cause an
exit that invokes it. On a nonzero exit while the installer still owns the
lock, cleanup attempts to move a promoted candidate to `failed-live` under the
staging tree and restore the backup only if the destination is absent. Those
moves are best effort. Cleanup then removes the staging tree, stops the
heartbeat, and removes the lock only if its owner token still matches; a
cleanup filesystem error can interrupt those later steps. See
[repository cleanup](../scripts/install.sh#L90-L139) and
[web cleanup](../apps/web/public/install.sh#L90-L139).

This is not guaranteed crash recovery: uncatchable termination, machine
failure, filesystem errors, or lost lock ownership can leave a stage, backup,
lock, or incomplete live state. In particular, cleanup does not roll back after
ownership is lost, and a later installer may reclaim a stale lock but does not
restore an orphaned backup. Inspect the destination and sibling paths before
manually recovering or deleting leftovers; do not remove a lock belonging to an
active installer.

After successful promotion, PATH setup is separate and best effort. If needed,
the installer creates sibling `.phantom-path.before.*` and
`.phantom-path.candidate.*` files in the selected shell startup file's parent,
checks the existing file and candidate, and moves the candidate into place.
Handled failures remove the temporary files and produce a warning; PATH failure
does not roll back the installation. An interruption can leave temporary files.
See the [PATH update flow](installer-path-update-flow.md) for the two files'
roles, comparison checks, and cleanup limits in the repository installer.
See [repository PATH handling](../scripts/install.sh#L305-L409) and
[final call](../scripts/install.sh#L535-L537), and
[web PATH handling](../apps/web/public/install.sh#L305-L409) and
[final call](../apps/web/public/install.sh#L535-L537).
