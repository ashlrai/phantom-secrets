# Quickstart temporary prefix reference

This reference describes the install commands displayed by
[`QuickStart.tsx`](../apps/web/src/components/landing/QuickStart.tsx). It covers
the panel's installer-script staging, not temporary paths used internally by
the installer or the final binary installation directory.

| Platform | Temporary name and parent | Environment-variable fallback |
| --- | --- | --- |
| macOS | `mktemp -d` creates a directory with the prefix `phantom-install.` under `TMPDIR`, using the template `phantom-install.XXXXXX`. | `${TMPDIR:-/tmp}` selects `/tmp` when `TMPDIR` is unset or empty. |
| Windows | No temporary directory is created by the displayed command. An installer file path under `$env:TEMP` has the prefix `phantom-install-`, followed by the release tag and a GUID, and ends in `.ps1`. | The displayed command specifies no fallback for `$env:TEMP`. |
| Linux | `mktemp -d` creates a directory with the prefix `phantom-install.` under `TMPDIR`, using the template `phantom-install.XXXXXX`. | `${TMPDIR:-/tmp}` selects `/tmp` when `TMPDIR` is unset or empty. |

On macOS and Linux, `mktemp` replaces the six `X` characters. The quoted
template allows spaces in the parent path. A nonempty but unusable `TMPDIR`
causes creation to fail; it does not trigger a retry under `/tmp`. Windows
constructs a file path before downloading the script, rather than creating a
directory. Cleanup is attempted on exit, but is not guaranteed. See the
[temporary directory usage guide](quickstart-temp-directory-usage.md) for the
sequence and cleanup limits.
