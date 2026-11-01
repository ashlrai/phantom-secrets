# Landing-page quickstart staging prefix reference

The macOS and Linux installer snippets in [`QuickStart.tsx`](../apps/web/src/components/landing/QuickStart.tsx)
each create a temporary directory for the downloaded installer. Select the
platform on the landing page for the current copyable command and review its
linked installer source before running it.

## macOS

The staging template is `${TMPDIR:-/tmp}/phantom-install.XXXXXX`. The directory
name begins with `phantom-install.`; `mktemp -d` replaces `XXXXXX` when it
creates a unique directory. The parent is `TMPDIR` when set and nonempty, or
`/tmp` when `TMPDIR` is unset or empty. Quoting preserves paths containing
spaces. The downloaded script is named `install.sh` inside that directory.

## Linux

The staging template is `${TMPDIR:-/tmp}/phantom-install.XXXXXX`. The directory
name begins with `phantom-install.`; `mktemp -d` replaces `XXXXXX` when it
creates a unique directory. The parent is `TMPDIR` when set and nonempty, or
`/tmp` when `TMPDIR` is unset or empty. Quoting preserves paths containing
spaces. The downloaded script is named `install.sh` inside that directory.

These directories stage the installer script, not the installed binaries or the
installer's separate archive staging. After the exit trap is installed, it
attempts to remove the script and then the empty directory; cleanup is best
effort and can leave artifacts. See the [cleanup review](quickstart-temp-cleanup-review.md)
for failure and interruption limits.
