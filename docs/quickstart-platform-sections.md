# Landing-page quickstart platform sections

The [landing-page install section](https://phm.dev/#install) is defined in
[`QuickStart.tsx`](../apps/web/src/components/landing/QuickStart.tsx). Its
operating-system selector lists **macOS**, **Windows**, and **Linux** in that
order. macOS is selected initially; selecting another platform displays its
card in place of the current card. Each card includes archive and SHA-256
sidecar links for two architectures, an installer source link, a caveat, and
one copyable command labeled “Download, verify, install, and check both
binaries.”

The blocks below are the command text displayed for the pinned release at the
time of this document. The page is the source for current copyable commands;
release identifiers and installer digests are defined in
[`public-release.ts`](../apps/web/src/lib/public-release.ts). The displayed
`$` and `PS>` prompts are decorative and are not part of the copied text.
Review the linked installer and the [installation guide](getting-started.md#exact-github-assets-macos-linux-and-windows) before running a command.

## macOS

The card lists Apple Silicon and Intel archives and says Keychain is used when
available. It notes that the release is not notarized. The command uses a
private temporary staging directory, verifies `install.sh` with `shasum`, runs
it, and checks both installed binaries; its exit trap attempts cleanup.

```bash
(
set -euo pipefail
umask 077
phantom_stage="$(mktemp -d "${TMPDIR:-/tmp}/phantom-install.XXXXXX")"
phantom_installer="$phantom_stage/install.sh"
trap 'rm -f -- "$phantom_installer"; rmdir -- "$phantom_stage" 2>/dev/null || true' EXIT
curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 --output "$phantom_installer" https://raw.githubusercontent.com/ashlrai/phantom-secrets/7a51ce512ec4aee12cc29ff859036af63fbe93db/scripts/install.sh
printf '%s  %s\n' b317eb9b3aa07532c6d8f21eda354bd5fb89dea94f9d0d06d3e7bb291cd136ca "$phantom_installer" | shasum -a 256 -c -
bash "$phantom_installer"
"$HOME/.phantom-secrets/bin/phantom" --version
"$HOME/.phantom-secrets/bin/phantom-mcp" --version
)
```

## Windows

The card lists ARM64 and x64 archives and says current-user Credential Manager
is used when available. It notes that the archives are not Authenticode-signed.
The PowerShell command downloads a unique temporary `install.ps1`, verifies it
with `Get-FileHash`, runs it, and checks both installed executables; `finally`
attempts to remove the temporary file.

```powershell
& {
$ErrorActionPreference = 'Stop'
$Installer = Join-Path $env:TEMP ('phantom-install-v0.7.9-{0}.ps1' -f [Guid]::NewGuid().ToString('N'))
try {
  Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/ashlrai/phantom-secrets/7a51ce512ec4aee12cc29ff859036af63fbe93db/scripts/install.ps1' -OutFile $Installer
  $Expected = '33e30a556283871ed8e9c1f3bd8a8c079f94f88dc2383d8c1d6667f14caca8f5'
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

## Linux

The card lists ARM64 and x64 GNU archives, with a glibc 2.35 symbol ceiling;
musl and Alpine are not published. It identifies keyutils as the initial vault
and warns that it is session-persistent, not reboot-persistent. The command
uses the same staging approach as macOS but verifies `install.sh` with
`sha256sum`. Its exit trap attempts cleanup.

```bash
(
set -euo pipefail
umask 077
phantom_stage="$(mktemp -d "${TMPDIR:-/tmp}/phantom-install.XXXXXX")"
phantom_installer="$phantom_stage/install.sh"
trap 'rm -f -- "$phantom_installer"; rmdir -- "$phantom_stage" 2>/dev/null || true' EXIT
curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 --output "$phantom_installer" https://raw.githubusercontent.com/ashlrai/phantom-secrets/7a51ce512ec4aee12cc29ff859036af63fbe93db/scripts/install.sh
printf '%s  %s\n' b317eb9b3aa07532c6d8f21eda354bd5fb89dea94f9d0d06d3e7bb291cd136ca "$phantom_installer" | sha256sum -c -
bash "$phantom_installer"
"$HOME/.phantom-secrets/bin/phantom" --version
"$HOME/.phantom-secrets/bin/phantom-mcp" --version
)
```

The Unix staging directory uses `TMPDIR` or `/tmp` if unset or empty. It is not
the install directory. Cleanup is attempted after the trap is installed and is
not guaranteed. On Linux, configure the managed passphrase before `phantom
init` when using the encrypted-file backend, and keep it out of agent process
inheritance.

## Shared numbered steps

After the selected card and installation note, both steps appear for every
platform. Their receipts are illustrative, not actual command output.

1. **Verify both v0.7.9 binaries:** check the versions on PATH. This is
   separate from the installed-path checks inside the platform command.

   ```bash
   phantom --version
   phantom-mcp --version
   ```

2. **Protect one supported project:** from an owned Git repository, retain an
   independent provider recovery copy and start with a supported HTTP API key.

   ```bash
   phantom init
   ```

See the [platform step map](quickstart-platform-step-map.md) for the order of
installation stages and the [command presentation guide](quickstart-command-presentation.md)
for how the copy controls work. Keep secret values and managed mappings out of
agent context and public output.
