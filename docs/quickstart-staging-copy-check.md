# Landing-page staging command copy check

[`QuickStart.tsx`](../apps/web/src/components/landing/QuickStart.tsx) displays
the Unix staging command in **two** occurrences: the `command` array of the
macOS entry in `PLATFORMS`, and the `command` array of the Linux entry. The
selected platform card's copy control renders that entry's `command` text and
copies the same string, so each occurrence is a separately displayed and
copied command. The Windows card displays a PowerShell block that stages a
temporary installer file under `$env:TEMP`; it contains no `mktemp` staging
command.

Both occurrences are the same twelve-line Bash subshell with exactly one
platform-specific line — the checksum step, `shasum -a 256 -c -` on macOS and
`sha256sum -c -` on Linux. The other eleven lines are shared verbatim: the
subshell wrapper, `set -euo pipefail`, `umask 077`, the
`mktemp -d "${TMPDIR:-/tmp}/phantom-install.XXXXXX"` staging directory, the
`phantom_installer` path inside it, the `EXIT` cleanup trap, the pinned-commit
`curl` download, `bash` execution of the verified installer, and both
installed-path version checks.

## Checking that both occurrences remain consistent

The two `command` arrays are independent source lists, so an edit to one
occurrence can silently drift from the other. The consistency check:

1. Extract both displayed commands — select macOS, then Linux, in the panel
   and copy each command, or read the two `command` arrays in
   `QuickStart.tsx` directly.
2. Compare them line by line. Exactly one line may differ — the checksum
   line, which must keep `shasum -a 256 -c -` on macOS and `sha256sum -c -`
   on Linux. Every other line must match byte for byte, in order, quotes
   included.
3. The check fails when any other line differs (a trap, `curl` flag, staged
   path, or version check changed on one platform only), when the checksum
   tools match or swap, or when the staging command stops appearing in
   exactly those two occurrences.

Run the automated form of this check from `apps/web`:

```sh
node --test tests/quickstart-staging-copy-check.test.cjs
```

The wider `npm test` suite covers each occurrence's download order, quoting,
and cleanup. The [staging comparison](quickstart-staging-comparison.md)
quotes every displayed line, and the
[snippet count](quickstart-stage-snippet-count.md) records why exactly two
occurrences exist. The panel and
[`public-release.ts`](../apps/web/src/lib/public-release.ts) remain the
source of the current commands and pinned values.
