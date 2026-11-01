# Quickstart temporary directory fallback

The macOS and Linux install panels in [`QuickStart.tsx`](../apps/web/src/components/landing/QuickStart.tsx)
each create a temporary directory for the downloaded installer. The panel is
the source for the complete, checksum-verified command; the lines below show
only its staging-directory assignment.

## macOS

```sh
phantom_stage="$(mktemp -d "${TMPDIR:-/tmp}/phantom-install.XXXXXX")"
```

`TMPDIR` selects the parent directory. If it is unset or empty, `${TMPDIR:-/tmp}`
uses `/tmp`. `mktemp -d` creates a unique directory with the prefix
`phantom-install.`; the six `X` characters are replaced by `mktemp`.

## Linux

```sh
phantom_stage="$(mktemp -d "${TMPDIR:-/tmp}/phantom-install.XXXXXX")"
```

This identical snippet uses `TMPDIR` as the parent, falls back to `/tmp` when
it is unset or empty, and creates a unique directory with the prefix
`phantom-install.`.

Both commands quote the template, so spaces and shell glob characters in the
parent are treated literally. A relative `TMPDIR` is relative to the shell's
current working directory. The parent must already exist and be writable:
an invalid nonempty `TMPDIR` makes `mktemp` fail before the download instead
of retrying under `/tmp`. The directory holds `install.sh`, not the installed
binaries. After the exit trap is installed, it attempts to
remove the script and then the empty directory; cleanup is not guaranteed.
See the [cleanup review](quickstart-temp-cleanup-review.md) for its limits.

Windows instead uses a temporary installer file under `$env:TEMP`; it does not
use this directory template or specify a fallback in the displayed command.
