# Quickstart temporary staging snippets

The landing page's [`QuickStart.tsx`](../apps/web/src/components/landing/QuickStart.tsx)
contains **two** temporary directory creation snippets: one in the `command`
array of the macOS entry in `PLATFORMS`, and one in the `command` array of the
Linux entry. Each appears in its selected platform's copyable install command.

The directory creation commands **match exactly**:

```sh
phantom_stage="$(mktemp -d "${TMPDIR:-/tmp}/phantom-install.XXXXXX")"
```

Each invocation creates a unique staging directory under `TMPDIR`, or `/tmp`
when `TMPDIR` is unset or empty. Quoting permits spaces in the temporary path.
The directory holds the downloaded installer, not the installed binaries; the
exit trap attempts to remove the installer and the empty directory, but cleanup
is not guaranteed. See the [cleanup review](quickstart-temp-cleanup-review.md)
for failure cases.

The Windows entry assigns a temporary installer file path under `$env:TEMP`;
it does not create a staging directory. The subsequent version checks and
`phantom init` steps do not create one in the displayed commands. The current
platform panel remains the source for the complete install command.
