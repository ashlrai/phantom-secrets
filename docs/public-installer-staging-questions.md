# Public Unix installer staging and cleanup questions

This review concerns [`apps/web/public/install.sh`](../apps/web/public/install.sh),
the public Bash installer, not the landing page's temporary download directory
or the PowerShell installer. It records current behavior and open questions;
it does not propose an installer change.

## Creation site

After deriving the destination's parent and name, creating the parent,
resolving it with `pwd -P`, and acquiring the sibling lock, the installer
creates the staging directory at [line 437](../apps/web/public/install.sh#L437):

```bash
stage_root="$(mktemp -d "$install_parent/.${install_name}.install.XXXXXX")"
```

The stage is a sibling of the live install, under the resolved install parent,
not under `TMPDIR`. For the default `$HOME/.phantom-secrets/bin` destination,
the template is `$HOME/.phantom-secrets/.bin.install.XXXXXX`, subject to parent
resolution. The installer sets the stage and its `download` and `candidate`
children to mode 700. The archive and checksum are downloaded there, and the
verified binaries and receipt are assembled in `candidate`. See
[destination and staging](../apps/web/public/install.sh#L425-L455) and
[validation](../apps/web/public/install.sh#L457-L496).

## Current cleanup and questions for review

The [exit trap](../apps/web/public/install.sh#L119-L139) attempts rollback on
failure only while the lock is still owned, removes the stage, then releases
the lock. HUP, INT, and TERM exit through that trap. During
[promotion](../apps/web/public/install.sh#L498-L522), a prior live install is
first moved to a sibling backup and, after validation, into the stage as
`previous-live`. The rollback moves are best effort, and a cleanup filesystem
error can interrupt subsequent cleanup. These observations raise questions:

- If stage creation or permissions fail, should the public script report a
  more specific error, and how should any remaining stage be identified?
- When a signal or validation failure occurs, are removal of the stage and
  release of the lock sufficiently observable if either operation fails?
- If moving the failed live install or restoring the backup fails, what should
  an operator inspect and preserve before attempting recovery? How should an
  orphaned backup be distinguished from an active installation?
- If lock ownership is lost, should stage removal proceed independently of
  rollback, and how can cleanup avoid interfering with another installer?
- After SIGKILL, a crash, or power loss, how should stale stages, backups, and
  locks be recognized and recovered without deleting an active installer's
  files? A later stale-lock reclaim does not restore an orphaned backup.
- Should interrupted [PATH updates](../apps/web/public/install.sh#L305-L399),
  which use separate temporary files outside `stage_root`, have their own
  recovery guidance? PATH update failure does not roll back promotion.

The offline [installer tests](../scripts/installers.test.js) cover the public
copy's staging failures and controlled rollback; they do not establish crash
recovery or guarantee cleanup after filesystem errors. See also the
[two-copy staging overview](installer-staging.md).
