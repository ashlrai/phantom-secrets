# Repository installer staging review

This review follows `stage_root` in [`scripts/install.sh`](../scripts/install.sh).
It covers the Unix repository installer, not the PowerShell installer. For a
comparison with the public web copy, see [Unix installer staging and cleanup](installer-staging.md).

## Creation and contents

- `stage_root` starts empty, before the cleanup trap is installed. The install
  parent is created and resolved to its physical path, and the installer
  acquires its sibling lock before creating a stage. See
  [initial state and traps](../scripts/install.sh#L28-L35),
  [cleanup registration](../scripts/install.sh#L119-L139), and
  [destination and lock setup](../scripts/install.sh#L425-L435).
- `mktemp -d` creates `.<install-name>.install.XXXXXX` in that canonical
  parent; the script explicitly sets it to mode 700 and creates `download` and
  `candidate` beneath it with mode 700. Failure at any of these steps aborts
  before downloading. This is a sibling of the live directory, not a directory
  inside it. See [stage creation](../scripts/install.sh#L437-L443).
- The archive and checksum sidecar are downloaded into `download`. After
  checking the sidecar, digest, and exact regular-file archive members, the
  installer extracts into `candidate`, checks both binary versions, and writes
  the source receipt there. See [download and validation](../scripts/install.sh#L450-L499).

## Promotion and cleanup

The installer derives a sibling backup name from the stage's random suffix.
With lock ownership checked around the moves, it moves any existing install to
that backup and moves `candidate` to the live destination. It validates the
live binaries and receipt again, then moves the old backup into the stage as
`previous-live`. The two moves are separate, so the live path can briefly be
absent. See [promotion](../scripts/install.sh#L501-L526).

The `EXIT` trap runs on success and ordinary failures; HUP, INT, and TERM exit
through it. On failure, **only while the installer still owns the lock**, it
tries to move a promoted install to `stage_root/failed-live`, then restore the
backup if the live path is absent. Both rollback moves are best effort. The
trap then removes the stage recursively and releases the lock if its owner
token still matches. A filesystem error during cleanup can interrupt those
later actions. See [cleanup and lock release](../scripts/install.sh#L90-L139).

This is not durable crash recovery: uncatchable termination, machine failure,
filesystem errors, or lost lock ownership can leave staging, a backup, a lock,
or incomplete live state. A later installer can reclaim a stale lock but does
not restore an orphaned backup. Inspect sibling paths and avoid removing an
active installer's lock when recovering manually. PATH updates happen after
promotion and use separate temporary files, not `stage_root`; failure there
warns rather than rolling back the installation. See [lock acquisition](../scripts/install.sh#L206-L303)
and [PATH update](../scripts/install.sh#L305-L403).

The [installer tests](../scripts/installers.test.js) exercise private staging,
cleanup after success and creation failures, and rollback after a controlled
post-promotion failure. They use local fixtures rather than a live release.
