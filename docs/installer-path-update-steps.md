# Unix installer PATH update steps

This lists, in order, the temporary-file creation and PATH update steps in
[`scripts/install.sh`](../scripts/install.sh). The web-served copy
(`apps/web/public/install.sh`) carries the identical `add_to_user_path`
function; the Windows installer (`scripts/install.ps1`) does not. For prose
descriptions, see the [PATH update flow](installer-path-update-flow.md) and
the [temporary-file reference](installer-path-update-reference.md).

## Temporary-file creation order

The installer creates its temporary artifacts in this order:

1. **Install lock** — after the install parent is resolved with `dirname`,
   `mkdir -p`, and `pwd -P`, `acquire_install_lock` creates
   `<install parent>/.<install name>.install.lock/` at mode 700 and writes an
   `owner` file at mode 600 that a background heartbeat refreshes.
2. **Staging root** — `mktemp -d` creates
   `<install parent>/.<install name>.install.XXXXXX/`, then `chmod 700`.
3. **Staging children** — `mkdir -m 700` creates `download/` (release archive
   and checksum sidecar) and `candidate/` (extracted binaries plus the
   `.phantom-install-source.json` receipt at mode 600).
4. **Backup name** — before promotion the script computes
   `<install parent>/.<install name>.backup.<stage suffix>` and refuses to
   continue if it already exists; the previous install directory is moved into
   it with `mv`, so nothing new is created at that path.
5. **PATH siblings** — only when the install directory is not already an exact
   `PATH` entry, `add_to_user_path` creates `.phantom-path.before.XXXXXX` and
   then `.phantom-path.candidate.XXXXXX` with `mktemp` in the resolved startup
   directory, under the script's `umask 077`. They never live inside the
   staging root.

The exit trap removes the staging root and releases the lock; the PATH
siblings are managed by `add_to_user_path` alone.

## PATH update steps in order

1. **PATH check** — the call site splits `$PATH` on `:` and requires an exact
   `grep -qxF` line match on `$INSTALL_DIR`. If present, no startup file is
   read or written.
2. **Argument check** — `add_to_user_path` returns 1 unless `bin` contains
   only characters matching `[A-Za-z0-9_./ -]`.
3. **Startup selection** — `basename "${SHELL:-bash}"` selects `~/.zshrc` for
   zsh, `~/.config/fish/config.fish` for fish, and `~/.bashrc` for anything
   else.
4. **Parent resolution** — `mkdir -p` creates the startup parent, `pwd -P`
   resolves it physically, and `rc` is rebuilt from the resolved parent.
5. **Before file** — `mktemp` creates `.phantom-path.before.XXXXXX`; a failure
   returns 1 with nothing else to remove.
6. **Candidate file** — `mktemp` creates `.phantom-path.candidate.XXXXXX`; a
   failure removes the before file and returns 1.
7. **Snapshot** — when `rc` exists (or is a symlink) it must be a regular,
   non-symlink file with exactly one link; the script records its
   device:inode:links:mode identity, `cp -p` copies it to the before file, and
   the identity is recorded again to catch a replacement mid-copy.
8. **Marker short-circuit** — if a line of the snapshot is exactly the
   `# phantom-secrets PATH` marker, both siblings are removed, the directory
   is reported as already wired, and the function returns 0 without editing
   `rc`.
9. **Candidate assembly** — for an existing `rc`, `cp -p` copies the snapshot
   to the candidate; for an absent `rc`, both files are truncated empty and
   `chmod 600`.
10. **PATH line** — the marker plus `set -gx PATH "<bin>" $PATH` (fish) or
    `export PATH="<bin>:$PATH"` (other shells) is appended to the candidate.
11. **Pre-move re-verification** — an absent `rc` must still be absent; an
    existing `rc` must keep its recorded identity, stay a regular non-symlink
    file, and match the snapshot byte-for-byte (`cmp -s`).
12. **Candidate identity** — the script records the candidate's identity for
    the post-move comparison.
13. **Move** — `mv -f` replaces `rc` with the candidate, then the before file
    is removed.
14. **Post-move verification** — `rc` must carry the recorded candidate
    identity, remain a regular non-symlink file, and contain the marker as a
    whole line; a failure returns 1 and the original file is not restored.
15. **Reporting** — success prints a "added to PATH" note pointing at the
    startup file; a `return 1` surfaces as the call-site `warn` telling the
    user to add the directory manually. The installed binaries stay in place
    either way.

## Failure and cleanup notes

- Every explicitly handled failure before the move removes both siblings — or
  only the before file when the candidate itself could not be created.
- After the move the candidate is gone and the before file is removed, so a
  post-move failure does not roll back the startup file.
- The installer's exit trap cleans the staging root and install lock, not the
  PATH siblings; interruption or filesystem errors can leave
  `.phantom-path.before.*` or `.phantom-path.candidate.*` files beside the
  startup file. Inspect leftovers and the startup file before removing
  anything, and avoid disturbing an active installer.
