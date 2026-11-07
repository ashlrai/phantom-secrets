# Quickstart temporary directory note

The copyable macOS and Linux install commands in
[`QuickStart.tsx`](../apps/web/src/components/landing/QuickStart.tsx) use this
staging directory assignment:

```sh
phantom_stage="$(mktemp -d "${TMPDIR:-/tmp}/phantom-install.XXXXXX")"
```

`mktemp -d` creates a unique directory from the `phantom-install.XXXXXX`
template. Its parent is `TMPDIR`, or `/tmp` when `TMPDIR` is unset or empty;
an unusable nonempty `TMPDIR` does not trigger a retry under `/tmp`. The
quoted path permits spaces. The command puts the downloaded `install.sh` in
this directory, which is separate from the final installation directory and
any archive staging performed by the installer itself.

Before the download, the subshell installs this cleanup trap:

```sh
trap 'rm -f -- "$phantom_installer"; rmdir -- "$phantom_stage" 2>/dev/null || true' EXIT
```

On subshell exit, including failures after the trap is installed, it attempts
to remove the installer file with `rm -f`, then remove the directory with
`rmdir` only if it is empty. Directory removal errors are suppressed, and
`|| true` prevents a failed `rmdir` from making the trap fail. Cleanup is best
effort: an interruption before trap installation, termination that prevents
the trap running, removal errors, or extra files can leave artifacts. The trap
does not remove the installed binaries.

The Windows command instead downloads to a GUID-named temporary installer file
under `$env:TEMP`; its `finally` block attempts to remove that file and
suppresses removal errors. It does not create a staging directory or specify a
fallback for `$env:TEMP`. See the [platform cleanup guide](quickstart-stage-cleanup.md)
for the full sequence.
