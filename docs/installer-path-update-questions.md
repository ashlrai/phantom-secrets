# Unix installer PATH update: failure-reporting questions

This review concerns the checked-in [`scripts/install.sh`](../scripts/install.sh#L305),
not the web-served copy or Windows installer. It records questions for a future
change; it does not propose that the current installer already answers them.

After the binaries are installed and validated, the installer updates the shell
startup file only if the install directory is absent from the current PATH.
The basename of `SHELL` selects `.zshrc`, `.config/fish/config.fish`, or
`.bashrc` for other shells. In that file's physical parent directory,
`add_to_user_path` creates two `mktemp` siblings:

| Temporary file template | Purpose |
| --- | --- |
| `.phantom-path.before.XXXXXX` | Snapshot of the original startup file, used for the marker check and pre-replacement comparison; empty when the file was absent. |
| `.phantom-path.candidate.XXXXXX` | Proposed startup file, containing the original content if present plus the marker and shell-specific PATH command. It is moved into place. |

These files can contain startup configuration. They begin under `umask 077`,
but `cp -p` can preserve the original file's attributes. See the
[PATH update flow](installer-path-update-flow.md) for checks and cleanup limits.

## What is reported today?

On a handled failure, the caller emits `could not update your shell PATH; add
… manually` and continues to the completion messages; the installed binaries
are not rolled back. Underlying commands may also emit diagnostics, while some
checks suppress them. An existing marker returns success without confirming it
points to the current install directory. A final verification failure occurs
after the candidate was moved and the snapshot removed, so the warning alone
does not establish whether the startup file changed or remains usable.
Interruption, unhandled failures, or failed cleanup may leave siblings behind;
the general exit trap does not remove these PATH files.

## Questions for maintainers

1. Should the warning distinguish preparation, concurrent-change checks,
   replacement, and post-move verification, so users know whether the startup
   file may already have changed? What recovery guidance is safe for each?
2. Should successful binary installation with failed PATH setup retain exit
   status zero, or should automation receive a distinct status or structured
   outcome? How would a change affect existing installation scripts?
3. Should cleanup failures or leftover temporary files be reported separately
   from the original failure, without masking it? How should interruptions be
   reported when cleanup cannot run?
4. Which underlying command errors should be surfaced or normalized, and how
   can diagnostics identify the affected operation without exposing startup
   contents or unnecessarily revealing local paths?
5. Should an existing marker with a stale install directory be reported as a
   separate outcome, rather than as already wired? How should multiple markers
   or manually edited entries be handled?
6. After a failed final verification, what evidence is needed before suggesting
   a retry or manual edit, given that the original snapshot is already removed?

The offline [installer tests](../scripts/installers.test.js) cover injected
pre-replacement failures and a final verification failure. They demonstrate
those cases, not every filesystem error or interruption.
