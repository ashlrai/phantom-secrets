# Landing-page quickstart staging comparison

The install panel in
[`QuickStart.tsx`](../apps/web/src/components/landing/QuickStart.tsx) shows
three platform cards, but the displayed commands contain **two**
distinct staging snippets: a Bash subshell shared by the macOS and Linux
cards, and a PowerShell block on the Windows card. The release tag, pinned
source commit, and installer digests come from
[`public-release.ts`](../apps/web/src/lib/public-release.ts); below,
`<release tag>`, `<pinned source commit>`, and `<pinned installer digest>`
stand in for them so these reference lines are not themselves copyable
commands. Use the panel for the current commands and inspect its linked
installer source before running anything.

## Snippet one: the Unix subshell (macOS and Linux)

Both Unix cards display the same twelve-line subshell. Eleven of its lines
are shared verbatim; only the checksum line differs, so the macOS and Linux
cards are not byte-identical even though their staging snippet is shared:

```sh
(
set -euo pipefail
umask 077
phantom_stage="$(mktemp -d "${TMPDIR:-/tmp}/phantom-install.XXXXXX")"
phantom_installer="$phantom_stage/install.sh"
trap 'rm -f -- "$phantom_installer"; rmdir -- "$phantom_stage" 2>/dev/null || true' EXIT
curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 --output "$phantom_installer" https://raw.githubusercontent.com/ashlrai/phantom-secrets/<pinned source commit>/scripts/install.sh
printf '%s  %s\n' <pinned installer digest> "$phantom_installer" | shasum -a 256 -c -   # macOS only
printf '%s  %s\n' <pinned installer digest> "$phantom_installer" | sha256sum -c -      # Linux only
bash "$phantom_installer"
"$HOME/.phantom-secrets/bin/phantom" --version
"$HOME/.phantom-secrets/bin/phantom-mcp" --version
)
```

Shared between macOS and Linux: the subshell wrapper `( … )`, the strict
mode (`set -euo pipefail`), the restrictive `umask 077`, the `mktemp -d`
staging directory under `${TMPDIR:-/tmp}` (with `/tmp` as the unset-or-empty
fallback), the `phantom_installer` path inside it, the `EXIT` trap that
attempts to remove the installer and then the empty directory, the
pinned-commit `curl` download with HTTPS and TLS restrictions, the `bash`
execution of the verified installer, and both installed-path version checks.

Platform-specific inside the shared snippet: macOS pipes the pinned digest
to `shasum -a 256 -c -`; Linux pipes the same digest to `sha256sum -c -`.

## Snippet two: the Windows PowerShell block

The Windows card displays an eighteen-line block; no line in it is shared
verbatim with the Unix subshell:

```powershell
& {
$ErrorActionPreference = 'Stop'
$Installer = Join-Path $env:TEMP ('phantom-install-<release tag>-{0}.ps1' -f [Guid]::NewGuid().ToString('N'))
try {
  Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/ashlrai/phantom-secrets/<pinned source commit>/scripts/install.ps1' -OutFile $Installer
  $Expected = '<pinned installer digest>'
  $Actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $Installer).Hash.ToLowerInvariant()
  if ($Actual -ne $Expected) { throw 'Phantom installer checksum mismatch' }
  & $Installer
  if (-not $?) { throw 'Phantom installer failed' }
  & "$env:USERPROFILE\.phantom-secrets\bin\phantom.exe" --version
  if (-not $?) { throw 'Phantom CLI verification failed' }
  & "$env:USERPROFILE\.phantom-secrets\bin\phantom-mcp.exe" --version
  if (-not $?) { throw 'Phantom MCP verification failed' }
} finally {
  Remove-Item -LiteralPath $Installer -Force -ErrorAction SilentlyContinue
}
}
```

## Shared steps, platform-specific lines

The two snippets perform the same staging steps with platform-specific
lines:

| Step | Unix line(s) | Windows line(s) |
|---|---|---|
| Group the block | `(` … `)` | `& {` … `}` |
| Stop on failure | `set -euo pipefail` | `$ErrorActionPreference = 'Stop'` |
| Restrict staging permissions | `umask 077` | none |
| Unique staging under the temp root | `mktemp -d` creates a `phantom-install.XXXXXX` directory under `${TMPDIR:-/tmp}` | `Join-Path $env:TEMP` names a `phantom-install-<release tag>-<GUID>.ps1` file; nothing is created yet |
| Name the staged installer | `phantom_installer="$phantom_stage/install.sh"` | `$Installer = Join-Path …` (the same line as staging) |
| Arm cleanup before downloading | `trap 'rm -f …; rmdir …' EXIT` | `try {` … `} finally {` … `Remove-Item -LiteralPath $Installer -Force -ErrorAction SilentlyContinue` … `}` |
| Download the pinned script | `curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 --output "$phantom_installer"` for `install.sh` | `Invoke-WebRequest -Uri '…install.ps1' -OutFile $Installer` |
| Verify the fixed SHA-256 digest | `printf '%s  %s\n' <pinned installer digest> "$phantom_installer"` piped to `shasum -a 256 -c -` (macOS) or `sha256sum -c -` (Linux) | `$Expected`/`$Actual` compared after `Get-FileHash -Algorithm SHA256`; a mismatch throws |
| Run the verified installer | `bash "$phantom_installer"` | `& $Installer` plus `if (-not $?) { throw 'Phantom installer failed' }` |
| Check both installed binaries | `"$HOME/.phantom-secrets/bin/phantom" --version` and `phantom-mcp` | `& "$env:USERPROFILE\.phantom-secrets\bin\phantom.exe" --version` and `phantom-mcp.exe`, each followed by a throw guard |

### Lines without a direct counterpart

- Unix only: `umask 077`; the `${TMPDIR:-/tmp}` fallback (the Windows block
  specifies no `$env:TEMP` fallback); and the `rmdir` of the empty staging
  directory, since Windows stages a file and has no directory to remove.
- Windows only: the `$Expected`/`$Actual` digest variables and the three
  `if (-not $?) { throw … }` guards — the subshell relies on `set -e`
  instead — and `[Guid]::NewGuid()` file naming, where Unix uses `mktemp`'s
  `XXXXXX` template.

## Steps shared by both snippets

- Stage the installer under the operating system's temporary root with a
  unique per-invocation name.
- Download the installer script pinned to the release source commit.
- Verify the fixed SHA-256 digest before executing — never after.
- Run the installer, then check both installed binaries' versions.
- Attempt cleanup on every exit path with errors suppressed; cleanup is best
  effort and not guaranteed.

## Scope

The Unix staging directory under `TMPDIR` (or `/tmp`) and the Windows
temporary installer file are not the install directory, and their cleanup
does not uninstall the binaries; the installers perform their own archive
staging (see [installer staging](installer-staging.md)). For ordering see the
[staging lifecycle](quickstart-staging-lifecycle.md), for failure cases the
[cleanup review](quickstart-temp-cleanup-review.md), and for the full
workflow [getting started](getting-started.md#exact-github-assets-macos-linux-and-windows).
