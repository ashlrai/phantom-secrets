# Phantom Secrets -- Windows one-liner installer.
#
#   irm https://phm.dev/install.ps1 | iex
#
# Downloads the latest signed release binary from GitHub, verifies SHA-256,
# extracts to %USERPROFILE%\.phantom-secrets\bin, and wires it into User PATH.
#
# Honors:
#   $env:PHANTOM_REPO         override repo (default: ashlrai/phantom-secrets)
#   $env:PHANTOM_INSTALL_DIR  override install dir (default: ~\.phantom-secrets\bin)
#   $env:PHANTOM_TAG          pin a specific release tag (default: latest)

$ErrorActionPreference = 'Stop'

function Write-PhSay  { param([string]$m) Write-Host "  -> phantom: $m" -ForegroundColor Magenta }
function Write-PhWarn { param([string]$m) Write-Host "  !  phantom: $m" -ForegroundColor Yellow }
function Write-PhDie  { param([string]$m) Write-Host "  X  phantom: $m" -ForegroundColor Red; exit 1 }

# Convert a Windows path (C:\Users\foo\bin) to a Git Bash / MSYS path
# (/c/Users/foo/bin). Git Bash inherits the Windows User PATH only at
# shell-start time -- so an already-running bash (e.g. Claude Code on
# Windows shells out through Git Bash) does NOT see new entries until the
# session restarts. Writing an explicit export to ~/.bashrc with the
# unix-style path covers that gap.
function ConvertTo-BashPath {
    param([Parameter(Mandatory)][string]$WinPath)
    $p = $WinPath -replace '\\', '/'
    if ($p -match '^([A-Za-z]):/(.*)$') {
        $drive = $Matches[1].ToLower()
        return "/$drive/$($Matches[2])"
    }
    return $p
}

function Add-ToBashrcPath {
    param([Parameter(Mandatory)][string]$WinBinDir)
    # NB: $home is a PowerShell read-only automatic variable -- using a different name.
    $homeDir = if ($env:HOME) { $env:HOME } else { $env:USERPROFILE }
    if (-not $homeDir) { return }
    $bashrc = Join-Path $homeDir '.bashrc'
    $bashPath = ConvertTo-BashPath -WinPath $WinBinDir
    $marker = "# phantom-secrets PATH ($bashPath)"
    try {
        if ((Test-Path $bashrc) -and (Select-String -Path $bashrc -SimpleMatch $marker -Quiet -ErrorAction SilentlyContinue)) {
            return
        }
        $line = "`n$marker`nexport PATH=`"$bashPath`:`$PATH`"`n"
        Add-Content -LiteralPath $bashrc -Value $line -Encoding UTF8
        Write-PhSay "wired $bashPath into $bashrc (for Git Bash / Claude Code)"
    } catch {
        Write-PhWarn "could not update $bashrc -- add '$bashPath' to your bash PATH manually. ($_)"
    }
}

$Repo       = if ($env:PHANTOM_REPO)        { $env:PHANTOM_REPO }        else { 'ashlrai/phantom-secrets' }
$InstallDir = if ($env:PHANTOM_INSTALL_DIR) { $env:PHANTOM_INSTALL_DIR } else { Join-Path $env:USERPROFILE '.phantom-secrets\bin' }
$PinTag     = $env:PHANTOM_TAG

# -----------------------------------------------------------------------
# 1. Detect target. Only x64 Windows is published.
# -----------------------------------------------------------------------

$cpuArch = (Get-CimInstance Win32_Processor).Architecture
if ($cpuArch -ne 9) {
    Write-PhDie 'only x64 Windows is published -- install from source: cargo install phantom-secrets'
}
$target = 'x86_64-pc-windows-msvc'
Write-PhSay "target: $target"

# -----------------------------------------------------------------------
# 2. Resolve release tag.
# -----------------------------------------------------------------------

if ($PinTag) {
    $tag = $PinTag
} else {
    Write-PhSay 'resolving latest release...'
    try {
        $rel = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest" -UseBasicParsing
    } catch {
        Write-PhDie "could not query GitHub releases: $($_.Exception.Message)"
    }
    $tag = $rel.tag_name
    if (-not $tag) { Write-PhDie 'could not determine latest release tag' }
}
Write-PhSay "release: $tag"

$archive = "phantom-$target.zip"
$url     = "https://github.com/$Repo/releases/download/$tag/$archive"

# -----------------------------------------------------------------------
# 3. Download + verify checksum.
# -----------------------------------------------------------------------

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $tmp | Out-Null
$archivePath = Join-Path $tmp $archive
try {
    Write-PhSay "downloading $archive..."
    try {
        Invoke-WebRequest -Uri $url -OutFile $archivePath -UseBasicParsing
    } catch {
        Write-PhDie "could not download ${url}: $($_.Exception.Message)"
    }
    try {
        Invoke-WebRequest -Uri "$url.sha256" -OutFile "$archivePath.sha256" -UseBasicParsing
    } catch {
        Write-PhDie 'could not download checksum sidecar -- refusing to install unverified binary'
    }

    $expected = ((Get-Content "$archivePath.sha256" -Raw).Trim() -split '\s+')[0].ToLower()
    $actual   = (Get-FileHash -Algorithm SHA256 $archivePath).Hash.ToLower()
    if ($expected -ne $actual) {
        Write-PhDie "SHA-256 mismatch: expected $expected, got $actual"
    }
    Write-PhSay 'checksum verified'

    # -------------------------------------------------------------------
    # 4. Extract + install.
    # -------------------------------------------------------------------

    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }
    Expand-Archive -LiteralPath $archivePath -DestinationPath $InstallDir -Force
    # Strip Mark-of-the-Web from the freshly-downloaded binaries so Windows
    # SmartScreen doesn't block first-run. Doesn't override WDAC/AppLocker.
    Get-ChildItem -Path $InstallDir -Filter '*.exe' -ErrorAction SilentlyContinue |
        ForEach-Object { Unblock-File -LiteralPath $_.FullName -ErrorAction SilentlyContinue }
    Write-PhSay "installed to $InstallDir"
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}

# -----------------------------------------------------------------------
# 5. Wire User PATH.
# -----------------------------------------------------------------------

$userPath = [Environment]::GetEnvironmentVariable('Path','User')
$userPathDirs = if ($userPath) { $userPath -split ';' | Where-Object { $_ } } else { @() }
if ($userPathDirs -notcontains $InstallDir) {
    $newUserPath = if ($userPath) { "$InstallDir;$userPath" } else { $InstallDir }
    [Environment]::SetEnvironmentVariable('Path', $newUserPath, 'User')
    # Make the new PATH visible to this same session, too.
    $env:Path = "$InstallDir;$env:Path"
    Write-PhSay "added $InstallDir to user PATH"
}

# Mirror the install dir into Git Bash's PATH so an already-running bash
# (Claude Code on Windows shells out through Git Bash) picks up phantom on
# next session start, not just whenever Windows User PATH propagates.
Add-ToBashrcPath -WinBinDir $InstallDir

# -----------------------------------------------------------------------
# 6. Verify.
# -----------------------------------------------------------------------

$exe = Join-Path $InstallDir 'phantom.exe'
if (Test-Path $exe) {
    try {
        $ver = (& $exe --version) 2>$null
        if (-not $ver) { $ver = 'unknown' }
        Write-PhSay "done. $ver"
        Write-PhSay 'restart your terminal -- and your Claude Code session, if any -- then try: phantom --help'
    } catch {
        Write-PhWarn "binary installed but did not run cleanly. Try: $exe --help"
    }
} else {
    Write-PhWarn "$exe not found after extract -- open $InstallDir to inspect"
}
