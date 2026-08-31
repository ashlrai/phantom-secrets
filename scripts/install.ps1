# Phantom Secrets -- Windows one-liner installer.
#
#   irm https://phm.dev/install.ps1 | iex
#
# Downloads a bounded HTTPS release, verifies its exact checksum/archive
# identity and both binary versions, then promotes a private sibling candidate
# into the live install directory with rollback.

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-PhSay  { param([string]$Message) Write-Host "  -> phantom: $Message" -ForegroundColor Magenta }
function Write-PhWarn { param([string]$Message) Write-Host "  !  phantom: $Message" -ForegroundColor Yellow }
function Write-PhDie  { param([string]$Message) Write-Host "  X  phantom: $Message" -ForegroundColor Red; exit 1 }

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
    $bashrc = Join-Path $homeDir '.bashrc'
    $marker = "# phantom-secrets PATH ($bashPath)"
    try {
        if ((Test-Path -LiteralPath $bashrc) -and
            (Select-String -LiteralPath $bashrc -SimpleMatch $marker -Quiet -ErrorAction SilentlyContinue)) {
            return
        }
        $quoted = "'$bashPath'"
        Add-Content -LiteralPath $bashrc -Value "`n$marker`nexport PATH=${quoted}:`$PATH`n" -Encoding UTF8
        Write-PhSay "wired $bashPath into $bashrc (for Git Bash / Claude Code)"
    } catch {
        Write-PhWarn "could not update $bashrc; add the install directory manually"
    }
}

function Test-AllowedDownloadUri {
    param([Parameter(Mandatory)][Uri]$Uri)
    if ($Uri.Scheme -ne 'https') { return $false }
    return @(
        'api.github.com',
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
    [System.IO.Directory]::CreateDirectory($Path) | Out-Null
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

$Repo = if ($env:PHANTOM_REPO) { $env:PHANTOM_REPO } else { 'ashlrai/phantom-secrets' }
if ($Repo -cnotmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$') { Write-PhDie 'invalid PHANTOM_REPO' }
$InstallDir = if ($env:PHANTOM_INSTALL_DIR) {
    $env:PHANTOM_INSTALL_DIR
} else {
    Join-Path $env:USERPROFILE '.phantom-secrets\bin'
}
$PinTag = $env:PHANTOM_TAG

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
[System.IO.Directory]::CreateDirectory($installParent) | Out-Null
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

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$handler = New-Object System.Net.Http.HttpClientHandler
$handler.AllowAutoRedirect = $false
$script:HttpClient = New-Object -TypeName System.Net.Http.HttpClient -ArgumentList @($handler)
$script:HttpClient.Timeout = [TimeSpan]::FromSeconds(120)
$script:HttpClient.DefaultRequestHeaders.UserAgent.ParseAdd('phantom-installer/1')

try {
    New-PrivateDirectory -Path $stageRoot
    $downloadDir = Join-Path $stageRoot 'download'
    $candidateDir = Join-Path $stageRoot 'candidate'
    New-PrivateDirectory -Path $downloadDir
    New-PrivateDirectory -Path $candidateDir

    if ($PinTag) {
        $tag = $PinTag
    } else {
        Write-PhSay 'resolving latest release...'
        $releaseJson = Join-Path $downloadDir 'latest.json'
        Invoke-PhDownload -Uri ([Uri]"https://api.github.com/repos/$Repo/releases/latest") `
            -OutFile $releaseJson -MaxBytes 1048576
        $release = Get-Content -LiteralPath $releaseJson -Raw | ConvertFrom-Json
        $tag = $release.tag_name
    }
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
    Write-PhSay 'archive identity verified'

    try {
        if (Test-Path -LiteralPath $InstallDir) {
            Move-Item -LiteralPath $InstallDir -Destination $backupPath
            $oldMoved = $true
        }
        Move-Item -LiteralPath $candidateDir -Destination $InstallDir
        $newMoved = $true
        Assert-ExactVersion -Binary (Join-Path $InstallDir 'phantom.exe') `
            -Product 'phantom' -ExpectedVersion $expectedVersion
        Assert-ExactVersion -Binary (Join-Path $InstallDir 'phantom-mcp.exe') `
            -Product 'phantom-mcp' -ExpectedVersion $expectedVersion
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
    $script:HttpClient.Dispose()
    $handler.Dispose()
    if (Test-Path -LiteralPath $stageRoot) {
        Remove-Item -LiteralPath $stageRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if (-not $installed) { exit 1 }
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

Write-PhSay "done. phantom $expectedVersion and phantom-mcp $expectedVersion"
Write-PhSay 'if Windows reports a verified binary is blocked, inspect it and run Unblock-File manually only if your policy permits'
Write-PhSay 'restart your terminal and Claude Code session, then try: phantom --help'
