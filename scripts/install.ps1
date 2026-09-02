# Phantom Secrets -- checksum-verifying Windows release installer.
#
# 1. Download install.ps1 from an exact, reviewed release tag to a local file.
# 2. Compare Get-FileHash -Algorithm SHA256 with the checksum published for
#    that exact source, then inspect the local script.
# 3. Run the reviewed local file: & .\install.ps1
#
# Downloads a bounded HTTPS release, verifies its exact checksum/archive
# identity and both binary versions, then promotes a private sibling candidate
# into the live install directory with rollback.

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-PhSay  { param([string]$Message) Write-Host "  -> phantom: $Message" -ForegroundColor Magenta }
function Write-PhWarn { param([string]$Message) Write-Host "  !  phantom: $Message" -ForegroundColor Yellow }
function Write-PhDie  { param([string]$Message) Write-Host "  X  phantom: $Message" -ForegroundColor Red; exit 1 }

if (-not ([System.Management.Automation.PSTypeName]'PhantomInstallerFileSystem').Type) {
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class PhantomInstallerFileSystem {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool MoveFileEx(
        string existingFileName,
        string newFileName,
        int flags
    );
}
'@
}

function Assert-NoReparsePathComponents {
    param([Parameter(Mandatory)][string]$Path)
    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $root = [System.IO.Path]::GetPathRoot($fullPath)
    if (-not $root -or $root.StartsWith('\\')) {
        throw 'install paths must use a local rooted drive'
    }
    $cursor = $root
    $relative = $fullPath.Substring($root.Length)
    $missing = $false
    foreach ($component in $relative.Split([char[]]@('\', '/'), [System.StringSplitOptions]::RemoveEmptyEntries)) {
        $cursor = Join-Path $cursor $component
        if ($missing) { continue }
        $item = Get-Item -LiteralPath $cursor -Force -ErrorAction SilentlyContinue
        if (-not $item) {
            $missing = $true
            continue
        }
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "refusing reparse-point path component: $cursor"
        }
        if ($cursor -ne $fullPath -and -not $item.PSIsContainer) {
            throw "install path ancestor is not a directory: $cursor"
        }
    }
    return $fullPath
}

function Assert-SafeInstallDirectoryOverride {
    param([Parameter(Mandatory)][string]$Path)
    if ($Path -notmatch '^[A-Za-z]:[\\/][A-Za-z0-9_. \\/-]+$' -or
        $Path.Split([char[]]@('\', '/')) -contains '..') {
        throw 'PHANTOM_INSTALL_DIR must be a local absolute path without control or shell-significant characters'
    }
}

function ConvertTo-BashPath {
    param([Parameter(Mandatory)][string]$WinPath)
    $path = $WinPath -replace '\\', '/'
    if ($path -match '^([A-Za-z]):/(.*)$') {
        return "/$($Matches[1].ToLower())/$($Matches[2])"
    }
    return $path
}

function Add-ToBashrcPath {
    param([Parameter(Mandatory)][string]$WinBinDir)
    $homeDir = if ($env:HOME) { $env:HOME } else { $env:USERPROFILE }
    if (-not $homeDir) { return }
    $bashPath = ConvertTo-BashPath -WinPath $WinBinDir
    if ($bashPath -match "[`r`n']") {
        Write-PhWarn 'could not safely add the install directory to Git Bash PATH'
        return
    }
    $bashrc = Join-Path ([System.IO.Path]::GetFullPath($homeDir)) '.bashrc'
    $marker = "# phantom-secrets PATH ($bashPath)"
    $tempPath = $null
    try {
        $parent = Split-Path -Parent $bashrc
        [void](Assert-NoReparsePathComponents -Path $parent)
        [System.IO.Directory]::CreateDirectory($parent) | Out-Null
        [void](Assert-NoReparsePathComponents -Path $parent)
        $before = [byte[]]@()
        $existingAcl = $null
        $existing = Get-Item -LiteralPath $bashrc -Force -ErrorAction SilentlyContinue
        if ($existing) {
            if ($existing.PSIsContainer -or
                (($existing.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)) {
                throw 'Git Bash rc must be one regular non-reparse file'
            }
            if ($existing.Length -gt 1048576) { throw 'Git Bash rc exceeds the 1 MiB safety limit' }
            $before = [System.IO.File]::ReadAllBytes($bashrc)
            $existingAcl = Get-Acl -LiteralPath $bashrc
        }
        $beforeText = [System.Text.Encoding]::UTF8.GetString($before)
        if ($beforeText.Contains($marker)) {
            return
        }
        $suffix = [System.Text.Encoding]::UTF8.GetBytes("`n$marker`nexport PATH='$bashPath':`$PATH`n")
        $candidate = New-Object byte[] ($before.Length + $suffix.Length)
        [Array]::Copy($before, 0, $candidate, 0, $before.Length)
        [Array]::Copy($suffix, 0, $candidate, $before.Length, $suffix.Length)
        $tempPath = Join-Path $parent ".bashrc.phantom.$([Guid]::NewGuid().ToString('N')).tmp"
        $stream = [System.IO.File]::Open(
            $tempPath,
            [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None
        )
        try {
            $stream.Write($candidate, 0, $candidate.Length)
            $stream.Flush($true)
        } finally {
            $stream.Dispose()
        }
        if ($existingAcl) { Set-Acl -LiteralPath $tempPath -AclObject $existingAcl }

        [void](Assert-NoReparsePathComponents -Path $parent)
        $current = Get-Item -LiteralPath $bashrc -Force -ErrorAction SilentlyContinue
        if ($existing) {
            if (-not $current -or $current.PSIsContainer -or
                (($current.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) -or
                -not [System.Collections.StructuralComparisons]::StructuralEqualityComparer.Equals(
                    $before,
                    [System.IO.File]::ReadAllBytes($bashrc)
                )) {
                throw 'Git Bash rc changed while it was being updated'
            }
        } elseif ($current) {
            throw 'Git Bash rc appeared while it was being updated'
        }
        $moveReplaceExisting = 0x1
        $moveWriteThrough = 0x8
        if (-not [PhantomInstallerFileSystem]::MoveFileEx(
            $tempPath,
            $bashrc,
            ($moveReplaceExisting -bor $moveWriteThrough)
        )) {
            throw [System.ComponentModel.Win32Exception]::new([Runtime.InteropServices.Marshal]::GetLastWin32Error())
        }
        $tempPath = $null
        $final = Get-Item -LiteralPath $bashrc -Force
        if ($final.PSIsContainer -or
            (($final.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw 'Git Bash rc final path is not a regular file'
        }
        Write-PhSay "wired $bashPath into $bashrc (for Git Bash / Claude Code)"
    } catch {
        Write-PhWarn "could not update $bashrc; add the install directory manually"
    } finally {
        if ($tempPath -and (Test-Path -LiteralPath $tempPath)) {
            Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-AllowedDownloadUri {
    param([Parameter(Mandatory)][Uri]$Uri)
    if ($Uri.Scheme -ne 'https') { return $false }
    return @(
        'github.com',
        'release-assets.githubusercontent.com',
        'objects.githubusercontent.com'
    ) -contains $Uri.DnsSafeHost.ToLowerInvariant()
}

function Invoke-PhDownload {
    param(
        [Parameter(Mandatory)][Uri]$Uri,
        [Parameter(Mandatory)][string]$OutFile,
        [Parameter(Mandatory)][long]$MaxBytes
    )
    Update-InstallLockHeartbeat
    if ($script:TestLocalReleaseDir) {
        if (-not (Test-AllowedDownloadUri -Uri $Uri)) {
            throw 'refusing non-HTTPS or untrusted download URL'
        }
        $fileName = [System.IO.Path]::GetFileName($Uri.AbsolutePath)
        $source = Join-Path $script:TestLocalReleaseDir $fileName
        $sourceItem = Get-Item -LiteralPath $source -ErrorAction Stop
        if ($sourceItem.PSIsContainer -or
            (($sourceItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) -or
            $sourceItem.Length -lt 1 -or $sourceItem.Length -gt $MaxBytes) {
            throw 'offline installer fixture is missing, unsafe, or exceeded its size limit'
        }
        [System.IO.File]::Copy($sourceItem.FullName, $OutFile, $false)
        return
    }
    $current = $Uri
    for ($redirects = 0; $redirects -le 3; $redirects++) {
        if (-not (Test-AllowedDownloadUri -Uri $current)) {
            throw 'refusing non-HTTPS or untrusted download URL'
        }
        $response = $script:HttpClient.GetAsync(
            $current,
            [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead
        ).GetAwaiter().GetResult()
        try {
            if ([int]$response.StatusCode -in 301,302,303,307,308) {
                if ($redirects -eq 3 -or -not $response.Headers.Location) {
                    throw 'download exceeded the redirect limit or returned an invalid redirect'
                }
                $current = [Uri]::new($current, $response.Headers.Location)
                continue
            }
            if (-not $response.IsSuccessStatusCode) {
                throw "download failed with HTTP status $([int]$response.StatusCode)"
            }
            if ($response.Content.Headers.ContentLength -and
                $response.Content.Headers.ContentLength.Value -gt $MaxBytes) {
                throw "download exceeded the $MaxBytes-byte limit"
            }

            $input = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
            $output = [System.IO.File]::Open($OutFile, [System.IO.FileMode]::CreateNew,
                [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
            try {
                $buffer = New-Object byte[] 65536
                [long]$total = 0
                while (($count = $input.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    $total += $count
                    if ($total -gt $MaxBytes) { throw "download exceeded the $MaxBytes-byte limit" }
                    $output.Write($buffer, 0, $count)
                    Update-InstallLockHeartbeat
                }
                $output.Flush($true)
            } finally {
                $output.Dispose()
                $input.Dispose()
            }
            return
        } finally {
            $response.Dispose()
        }
    }
    throw 'download exceeded the redirect limit'
}

function New-PrivateDirectory {
    param([Parameter(Mandatory)][string]$Path)
    [void](Assert-NoReparsePathComponents -Path $Path)
    [System.IO.Directory]::CreateDirectory($Path) | Out-Null
    [void](Assert-NoReparsePathComponents -Path $Path)
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetOwner($identity)
    $acl.SetAccessRuleProtection($true, $false)
    $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $rule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList @(
        $identity,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        $inherit,
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow
    )
    $acl.AddAccessRule($rule) | Out-Null
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Get-PositiveInstallerSetting {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][int]$Default
    )
    $raw = [Environment]::GetEnvironmentVariable($Name)
    if (-not $raw) { return $Default }
    [int]$parsed = 0
    if (-not [int]::TryParse($raw, [ref]$parsed) -or $parsed -lt 1) {
        throw "$Name must be a positive integer"
    }
    return $parsed
}

function Update-InstallLockHeartbeat {
    if (-not $script:InstallLock) { return }
    $bytes = [System.Text.Encoding]::ASCII.GetBytes("$($script:InstallLock.Token)`n")
    $stream = $script:InstallLock.Stream
    $stream.Position = 0
    $stream.SetLength(0)
    $stream.Write($bytes, 0, $bytes.Length)
    $stream.Flush($true)
}

function Acquire-InstallLock {
    param(
        [Parameter(Mandatory)][string]$Parent,
        [Parameter(Mandatory)][string]$Name
    )
    $waitSeconds = Get-PositiveInstallerSetting -Name 'PHANTOM_INSTALL_LOCK_WAIT_SECONDS' -Default 30
    $staleSeconds = Get-PositiveInstallerSetting -Name 'PHANTOM_INSTALL_LOCK_STALE_SECONDS' -Default 300
    $heartbeatSeconds = Get-PositiveInstallerSetting -Name 'PHANTOM_INSTALL_LOCK_HEARTBEAT_SECONDS' -Default 5
    if ($heartbeatSeconds -ge $staleSeconds) {
        throw 'install lock heartbeat must be shorter than stale timeout'
    }
    $lockPath = Join-Path $Parent ".$Name.install.lock"
    $ownerPath = Join-Path $lockPath 'owner'
    $token = [Guid]::NewGuid().ToString('N') + [Guid]::NewGuid().ToString('N')
    $deadline = [DateTime]::UtcNow.AddSeconds($waitSeconds)

    while ($true) {
        if (Test-Path -LiteralPath $lockPath) {
            $lockItem = Get-Item -LiteralPath $lockPath
            if (-not $lockItem.PSIsContainer -or
                (($lockItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)) {
                throw 'install lock is not a regular directory'
            }
        } else {
            New-PrivateDirectory -Path $lockPath
        }

        try {
            $stream = [System.IO.File]::Open(
                $ownerPath,
                [System.IO.FileMode]::CreateNew,
                [System.IO.FileAccess]::ReadWrite,
                [System.IO.FileShare]::None
            )
            $script:InstallLock = [PSCustomObject]@{
                Path = $lockPath
                OwnerPath = $ownerPath
                Token = $token
                Stream = $stream
            }
            Update-InstallLockHeartbeat
            return
        } catch [System.IO.IOException] {
            if (-not (Test-Path -LiteralPath $ownerPath)) {
                Start-Sleep -Milliseconds 50
                continue
            }
            $ownerItem = Get-Item -LiteralPath $ownerPath
            if ($ownerItem.PSIsContainer -or
                (($ownerItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)) {
                throw 'install lock owner is not a regular file'
            }
            $ageSeconds = ([DateTime]::UtcNow - $ownerItem.LastWriteTimeUtc).TotalSeconds
            if ($ageSeconds -gt $staleSeconds) {
                $stalePath = "$lockPath.stale.$token"
                try {
                    Move-Item -LiteralPath $lockPath -Destination $stalePath -ErrorAction Stop
                    Remove-Item -LiteralPath $stalePath -Recurse -Force
                    continue
                } catch {
                    # An active owner keeps the file open without sharing; it cannot be stolen.
                }
            }
            if ([DateTime]::UtcNow -ge $deadline) {
                throw 'timed out waiting for another Phantom installer'
            }
            Start-Sleep -Milliseconds 200
        }
    }
}

function Release-InstallLock {
    if (-not $script:InstallLock) { return }
    $owned = $script:InstallLock
    $script:InstallLock = $null
    $owned.Stream.Dispose()
    try {
        if ((Test-Path -LiteralPath $owned.OwnerPath) -and
            ((Get-Content -LiteralPath $owned.OwnerPath -Raw).Trim() -ceq $owned.Token)) {
            Remove-Item -LiteralPath $owned.Path -Recurse -Force
        }
    } catch {
        Write-PhWarn 'could not remove the completed installer lock; it can be recovered after its stale timeout'
    }
}

function Assert-ExactVersion {
    param(
        [Parameter(Mandatory)][string]$Binary,
        [Parameter(Mandatory)][string]$Product,
        [Parameter(Mandatory)][string]$ExpectedVersion
    )
    $item = Get-Item -LiteralPath $Binary
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Product is a reparse point"
    }
    $start = New-Object System.Diagnostics.ProcessStartInfo
    $start.FileName = $Binary
    $start.Arguments = '--version'
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $start
    if (-not $process.Start()) { throw "$Product --version did not start" }
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit(10000)) {
        $process.Kill()
        throw "$Product --version timed out"
    }
    $process.WaitForExit()
    $output = $stdout.GetAwaiter().GetResult().TrimEnd([char[]]"`r`n")
    $null = $stderr.GetAwaiter().GetResult()
    if ($process.ExitCode -ne 0 -or $output -cne "$Product $ExpectedVersion") {
        throw "$Product reported an unexpected version"
    }
}

$CanonicalRepo = 'ashlrai/phantom-secrets'
$CandidateTag = 'v0.7.4'
$Repo = $CanonicalRepo
$PinTag = $CandidateTag
$script:TestLocalReleaseDir = $null
$disablePathPersistence = $false
$failAfterPromotion = $false
# These inputs are harness-only: local release fixtures and the gated
# post-promotion fault prove installer integrity and rollback without exposing
# production repository, tag, or transaction controls.
if ($env:PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES -ceq '1') {
    if ($env:PHANTOM_REPO) { $Repo = $env:PHANTOM_REPO }
    if ($env:PHANTOM_TAG) { $PinTag = $env:PHANTOM_TAG }
    if ($env:PHANTOM_TEST_LOCAL_RELEASE_DIR) {
        if (-not [System.IO.Path]::IsPathFullyQualified($env:PHANTOM_TEST_LOCAL_RELEASE_DIR)) {
            Write-PhDie 'PHANTOM_TEST_LOCAL_RELEASE_DIR must be an absolute regular directory'
        }
        $fixtureItem = Get-Item -LiteralPath $env:PHANTOM_TEST_LOCAL_RELEASE_DIR -ErrorAction Stop
        if (-not $fixtureItem.PSIsContainer -or
            (($fixtureItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)) {
            Write-PhDie 'PHANTOM_TEST_LOCAL_RELEASE_DIR must be an absolute regular directory'
        }
        $script:TestLocalReleaseDir = $fixtureItem.FullName
    }
    $disablePathPersistence = $env:PHANTOM_TEST_DISABLE_PATH_PERSISTENCE -ceq '1'
    if (Test-Path Env:PHANTOM_TEST_FAIL_AFTER_PROMOTION) {
        if ($env:PHANTOM_TEST_FAIL_AFTER_PROMOTION -cne '1') {
            Write-PhDie 'PHANTOM_TEST_FAIL_AFTER_PROMOTION must be 1 when set'
        }
        $failAfterPromotion = $true
    }
} elseif ($env:PHANTOM_REPO -or $env:PHANTOM_TAG -or
    $env:PHANTOM_TEST_LOCAL_RELEASE_DIR -or $env:PHANTOM_TEST_DISABLE_PATH_PERSISTENCE -or
    (Test-Path Env:PHANTOM_TEST_FAIL_AFTER_PROMOTION)) {
    Write-PhDie 'installer test overrides require PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES=1'
}
if ($Repo -cnotmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$') { Write-PhDie 'invalid PHANTOM_REPO' }
$InstallDir = if ($env:PHANTOM_INSTALL_DIR) {
    Assert-SafeInstallDirectoryOverride -Path $env:PHANTOM_INSTALL_DIR
    $env:PHANTOM_INSTALL_DIR
} else {
    Join-Path $env:USERPROFILE '.phantom-secrets\bin'
}

$architecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
switch ($architecture) {
    'X64'   { $target = 'x86_64-pc-windows-msvc' }
    'Arm64' { $target = 'aarch64-pc-windows-msvc' }
    default { Write-PhDie "unsupported Windows architecture: $architecture" }
}
Write-PhSay "target: $target"

$InstallDir = [System.IO.Path]::GetFullPath($InstallDir)
$root = [System.IO.Path]::GetPathRoot($InstallDir).TrimEnd('\')
if ($InstallDir.TrimEnd('\') -eq $root) { Write-PhDie 'refusing to install into filesystem root' }
$installParent = Split-Path -Parent $InstallDir
$installName = Split-Path -Leaf $InstallDir
if (-not $installName) { Write-PhDie 'invalid install directory' }
[void](Assert-NoReparsePathComponents -Path $installParent)
[System.IO.Directory]::CreateDirectory($installParent) | Out-Null
[void](Assert-NoReparsePathComponents -Path $installParent)
if (Test-Path -LiteralPath $InstallDir) {
    $liveItem = Get-Item -LiteralPath $InstallDir
    if (-not $liveItem.PSIsContainer -or
        (($liveItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)) {
        Write-PhDie 'refusing a non-directory or reparse-point install path'
    }
}

$stageRoot = Join-Path $installParent ".$installName.install.$([Guid]::NewGuid().ToString('N'))"
$backupPath = Join-Path $installParent ".$installName.backup.$([Guid]::NewGuid().ToString('N'))"
$oldMoved = $false
$newMoved = $false
$installed = $false
$script:InstallLock = $null
$handler = $null
$script:HttpClient = $null

try {
    Acquire-InstallLock -Parent $installParent -Name $installName
    if (-not $script:TestLocalReleaseDir) {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $handler = New-Object System.Net.Http.HttpClientHandler
        $handler.AllowAutoRedirect = $false
        $script:HttpClient = New-Object -TypeName System.Net.Http.HttpClient -ArgumentList @($handler)
        $script:HttpClient.Timeout = [TimeSpan]::FromSeconds(120)
        $script:HttpClient.DefaultRequestHeaders.UserAgent.ParseAdd('phantom-installer/1')
    }

    New-PrivateDirectory -Path $stageRoot
    $downloadDir = Join-Path $stageRoot 'download'
    $candidateDir = Join-Path $stageRoot 'candidate'
    New-PrivateDirectory -Path $downloadDir
    New-PrivateDirectory -Path $candidateDir

    $tag = $PinTag
    if (-not $tag -or
        $tag -cnotmatch '^v?[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$') {
        throw 'release tag is not strict semantic version syntax'
    }
    $expectedVersion = $tag -replace '^v', ''
    Write-PhSay "release: $tag"

    $archive = "phantom-$target.zip"
    $url = [Uri]"https://github.com/$Repo/releases/download/$tag/$archive"
    $archivePath = Join-Path $downloadDir $archive
    $checksumPath = "$archivePath.sha256"
    Write-PhSay "downloading $archive..."
    Invoke-PhDownload -Uri $url -OutFile $archivePath -MaxBytes 104857600
    Invoke-PhDownload -Uri ([Uri]"$url.sha256") -OutFile $checksumPath -MaxBytes 1024

    $sidecar = Get-Content -LiteralPath $checksumPath -Raw
    $match = [regex]::Match($sidecar, '\A([0-9A-Fa-f]{64})  ([^\r\n\s]+)\r?\n?\z')
    if (-not $match.Success -or $match.Groups[2].Value -cne $archive) {
        throw 'checksum sidecar must contain one exact digest and archive filename'
    }
    $expected = $match.Groups[1].Value.ToLowerInvariant()
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $archivePath).Hash.ToLowerInvariant()
    if ($expected -cne $actual) { throw 'SHA-256 mismatch' }
    Write-PhSay 'checksum verified'

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [System.IO.Compression.ZipFile]::OpenRead($archivePath)
    try {
        $entries = @($zip.Entries)
        $names = @($entries | ForEach-Object { $_.FullName } | Sort-Object)
        if ($entries.Count -ne 2 -or
            $names[0] -cne 'phantom-mcp.exe' -or $names[1] -cne 'phantom.exe') {
            throw 'release archive must contain exactly phantom.exe and phantom-mcp.exe'
        }
        foreach ($entry in $entries) {
            if ($entry.Name -cne $entry.FullName -or -not $entry.Name) {
                throw 'release archive contains a path or directory entry'
            }
            $unixType = (($entry.ExternalAttributes -shr 16) -band 0xF000)
            $dosAttributes = ($entry.ExternalAttributes -band 0xFFFF)
            $isDirectory = (($dosAttributes -band [int][System.IO.FileAttributes]::Directory) -ne 0)
            $isReparsePoint = (($dosAttributes -band [int][System.IO.FileAttributes]::ReparsePoint) -ne 0)
            if (($unixType -ne 0 -and $unixType -ne 0x8000) -or $isDirectory -or $isReparsePoint) {
                throw 'release archive contains a link or non-regular entry'
            }
            $destination = Join-Path $candidateDir $entry.Name
            [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $destination, $false)
        }
    } finally {
        $zip.Dispose()
    }

    foreach ($name in @('phantom.exe', 'phantom-mcp.exe')) {
        $item = Get-Item -LiteralPath (Join-Path $candidateDir $name)
        if ($item.PSIsContainer -or
            (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw "$name is not a regular file"
        }
    }
    Assert-ExactVersion -Binary (Join-Path $candidateDir 'phantom.exe') `
        -Product 'phantom' -ExpectedVersion $expectedVersion
    Assert-ExactVersion -Binary (Join-Path $candidateDir 'phantom-mcp.exe') `
        -Product 'phantom-mcp' -ExpectedVersion $expectedVersion
    $receipt = [ordered]@{
        schema_version = 1
        source = 'direct'
        version = $expectedVersion
        target = $target
    } | ConvertTo-Json -Compress
    $receiptPath = Join-Path $candidateDir '.phantom-install-source.json'
    [System.IO.File]::WriteAllText(
        $receiptPath,
        "$receipt`n",
        (New-Object System.Text.UTF8Encoding($false))
    )
    Write-PhSay 'archive identity verified'

    try {
        if (Test-Path -LiteralPath $InstallDir) {
            Move-Item -LiteralPath $InstallDir -Destination $backupPath
            $oldMoved = $true
        }
        Move-Item -LiteralPath $candidateDir -Destination $InstallDir
        $newMoved = $true
        if ($failAfterPromotion) {
            throw 'test-only injected failure after promotion'
        }
        Assert-ExactVersion -Binary (Join-Path $InstallDir 'phantom.exe') `
            -Product 'phantom' -ExpectedVersion $expectedVersion
        Assert-ExactVersion -Binary (Join-Path $InstallDir 'phantom-mcp.exe') `
            -Product 'phantom-mcp' -ExpectedVersion $expectedVersion
        $liveReceiptPath = Join-Path $InstallDir '.phantom-install-source.json'
        $liveReceiptItem = Get-Item -LiteralPath $liveReceiptPath
        if ($liveReceiptItem.PSIsContainer -or
            (($liveReceiptItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) -or
            ((Get-Content -LiteralPath $liveReceiptPath -Raw).Trim() -cne $receipt)) {
            throw 'install source receipt failed final validation'
        }
    } catch {
        if ($newMoved -and (Test-Path -LiteralPath $InstallDir)) {
            Move-Item -LiteralPath $InstallDir -Destination (Join-Path $stageRoot 'failed-live')
            $newMoved = $false
        }
        if ($oldMoved -and (Test-Path -LiteralPath $backupPath)) {
            Move-Item -LiteralPath $backupPath -Destination $InstallDir
            $oldMoved = $false
        }
        throw
    }
    if ($oldMoved) {
        Move-Item -LiteralPath $backupPath -Destination (Join-Path $stageRoot 'previous-live')
        $oldMoved = $false
    }
    $newMoved = $false
    $installed = $true
    Write-PhSay "installed to $InstallDir"
} catch {
    Write-PhDie $_.Exception.Message
} finally {
    if ($script:HttpClient) { $script:HttpClient.Dispose() }
    if ($handler) { $handler.Dispose() }
    if (Test-Path -LiteralPath $stageRoot) {
        Remove-Item -LiteralPath $stageRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
    Release-InstallLock
}

if (-not $installed) { exit 1 }
if ($disablePathPersistence) {
    Write-PhSay 'test mode: persistent PATH mutation skipped'
} else {
    try {
        $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
        $userPathDirs = if ($userPath) { @($userPath -split ';' | Where-Object { $_ }) } else { @() }
        if ($userPathDirs -notcontains $InstallDir) {
            $newUserPath = if ($userPath) { "$InstallDir;$userPath" } else { $InstallDir }
            [Environment]::SetEnvironmentVariable('Path', $newUserPath, 'User')
            $env:Path = "$InstallDir;$env:Path"
            Write-PhSay "added $InstallDir to user PATH"
        }
        Add-ToBashrcPath -WinBinDir $InstallDir
    } catch {
        Write-PhWarn "could not update PATH; add $InstallDir manually"
    }
}

Write-PhSay "done. phantom $expectedVersion and phantom-mcp $expectedVersion"
Write-PhSay 'if Windows reports a verified binary is blocked, inspect it and run Unblock-File manually only if your policy permits'
Write-PhSay 'restart your terminal and Claude Code session, then try: phantom --help'
