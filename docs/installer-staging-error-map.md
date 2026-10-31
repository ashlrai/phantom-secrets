# Repository Unix installer: staging error map

This map describes [`scripts/install.sh`](../scripts/install.sh), not the web
copy or PowerShell installer. The install directory's physical parent holds the
private stage (`.<name>.install.<suffix>`), lock (`.<name>.install.lock`), and,
during an upgrade, backup (`.<name>.backup.<suffix>`). The installer creates and
canonicalizes the parent and acquires the lock before staging. A parent or lock
failure happens before the stage exists; an unhandled parent filesystem error
may have only the underlying command's diagnostic. See
[destination setup](../scripts/install.sh#L425-L435) and
[lock acquisition](../scripts/install.sh#L206-L303).

## Creation failures

All three stage failures happen before any release download or live-directory
promotion. The installer exits with status 1 and invokes the EXIT cleanup trap.
The command itself may also print a filesystem diagnostic.

| Failing operation | Installer diagnostic | Cleanup state |
| --- | --- | --- |
| `mktemp -d` for the private sibling | `could not create a private staging directory in …` | `stage_root` is normally empty; there is no named stage for the trap to remove. |
| `chmod 700` on the stage | `could not secure the staging directory` | The created stage is removed if cleanup succeeds. |
| `mkdir -m 700` for `download` and `candidate` | `could not create staging directories` | A partially created tree is removed if cleanup succeeds. |

See [stage creation](../scripts/install.sh#L437-L443),
[initial state](../scripts/install.sh#L28-L35), and
[download start](../scripts/install.sh#L450-L457). The cleanup trap removes the
lock only when its recorded owner still matches. Removal failures and abnormal
termination qualify these outcomes, as described below.

## Cleanup and rollback failures

The [EXIT trap](../scripts/install.sh#L119-L139) runs on normal exit and ordinary
errors; HUP, INT, and TERM exit through it with statuses 129, 130, and 143.
For a nonzero exit, rollback is attempted only while the installer still owns
the lock. The flags set around [promotion](../scripts/install.sh#L501-L526)
determine which moves are attempted:

| Condition or failing operation | Effect |
| --- | --- |
| Lock ownership lost before cleanup | Both rollback moves are skipped. Stage removal is still attempted; the live directory and any sibling backup need inspection. |
| Moving the promoted live directory to `stage_root/failed-live` fails | The error is suppressed; the live path normally remains occupied, so the backup is not restored. The stage is still removed and the backup remains alongside the live directory. |
| Restoring the backup to an absent live path fails | The error is suppressed; the live path may remain absent and the backup remains alongside it. The stage is still removed, including any candidate moved to `failed-live`. |
| Removing the stage with `rm -rf` fails | The underlying command may report an error. Under `set -e`, cleanup can stop before stopping the heartbeat or releasing the lock, and the cleanup command's status can replace the original exit status. A partially removed stage and lock can remain, even after successful promotion. |
| Removing the owned lock fails | The underlying command may report an error and cleanup can exit with that status. The heartbeat has already been stopped, but the lock can remain. A lock whose owner no longer matches is deliberately left alone. |

The rollback moves use `|| true`, so their failure does not itself change the
original error status or produce an installer warning. If stage and lock removal
succeed, cleanup exits with the status captured on entry. See
[lock release](../scripts/install.sh#L90-L106) and
[shell error settings](../scripts/install.sh#L11-L12).

Uncatchable termination, machine failure, and filesystem errors can leave a
stage, lock, backup, or incomplete live install. A later installer may reclaim
a stale lock; it does not restore an orphaned backup. Before manual recovery,
inspect the live directory and sibling paths, preserve any needed backup, and
make sure no installer owns the lock. Do not assume a leftover stage or backup
is safe to delete. PATH setup occurs separately after promotion; its handled
failure warns without rolling back the install. See
[stale lock handling](../scripts/install.sh#L282-L303) and
[PATH handling](../scripts/install.sh#L527-L533).

The offline [installer tests](../scripts/installers.test.js) inject each stage
creation failure and rollback move failures, and check the resulting live,
backup, stage, and lock state. These tests do not establish recovery from every
filesystem error or uncatchable termination.
