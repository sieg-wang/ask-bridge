# install.ps1 for Windows PowerShell
param(
    [switch]$Local,
    [string]$LocalPath = ""
)

$ErrorActionPreference = "Stop"

Write-Host "Starting Ask Bridge installation for Windows..." -ForegroundColor Cyan

function Get-AskBridgeParentPid {
    try {
        $currentPid = $PID
        $seen = @{}

        for ($depth = 0; $depth -lt 16; $depth++) {
            $current = Get-CimInstance Win32_Process -Filter "ProcessId = $currentPid" -ErrorAction SilentlyContinue
            if (-not $current -or -not $current.ParentProcessId) {
                return $null
            }

            if ($seen.ContainsKey([int]$currentPid)) {
                return $null
            }
            $seen[[int]$currentPid] = $true

            $parentPid = [int]$current.ParentProcessId
            $parent = Get-CimInstance Win32_Process -Filter "ProcessId = $parentPid" -ErrorAction SilentlyContinue
            if (-not $parent) {
                return $null
            }

            $parentCommand = $parent.CommandLine
            if ($parent.Name -in @("ask.exe", "ask-bridge.exe")) {
                return [int]$parent.ProcessId
            }

            if ($parentCommand -and $parentCommand -match '\b(?:\.\\)?ask(?:-bridge)?(?:\.exe)?\b.*\bupdate\b') {
                return [int]$parent.ProcessId
            }

            $currentPid = $parentPid
        }
    } catch {
        return $null
    }

    return $null
}

function Stop-AskBridgeParentForUpdate {
    $targetPids = @()
    $parentPid = Get-AskBridgeParentPid
    if ($parentPid) {
        $targetPids += [int]$parentPid
    }

    if ($targetPids.Count -eq 0) {
        try {
            $sessionId = $null
            $self = Get-CimInstance Win32_Process -Filter "ProcessId = $PID" -ErrorAction SilentlyContinue
            if ($self -and $self.SessionId) {
                $sessionId = $self.SessionId
            }

            $allProcesses = Get-CimInstance Win32_Process -Filter "Name='ask.exe' OR Name='ask-bridge.exe'" -ErrorAction SilentlyContinue
            foreach ($process in $allProcesses) {
                if ($sessionId -ne $null -and $process.SessionId -ne $sessionId) {
                    continue
                }
                if ($process.ProcessId -ne $PID) {
                    $targetPids += [int]$process.ProcessId
                }
            }
        } catch {
            Write-Host "Warning: unable to discover running ask processes by fallback scan ($($_.Exception.Message))." -ForegroundColor Yellow
        }
    }

    $targetPids = $targetPids | Sort-Object -Unique
    if ($targetPids.Count -eq 0) {
        return
    }

    foreach ($pid in $targetPids) {
        $targetProcess = Get-CimInstance Win32_Process -Filter "ProcessId = $pid" -ErrorAction SilentlyContinue
        if (-not $targetProcess) {
            continue
        }

        Write-Host "Stopping running ask-bridge process (PID $pid) to replace binaries safely." -ForegroundColor Cyan
        try {
            Stop-Process -Id $pid -Force -ErrorAction Stop
        } catch {
            Write-Host "Warning: failed to stop PID $pid automatically ($($_.Exception.Message))." -ForegroundColor Yellow
        }
    }
}

function Copy-ItemWithRetry {
    param(
        [Parameter(Mandatory)] [string] $Source,
        [Parameter(Mandatory)] [string] $Destination
    )

    for ($attempt = 1; $attempt -le 10; $attempt++) {
        try {
            Copy-Item -Path $Source -Destination $Destination -Force
            return
        } catch {
            if ($attempt -eq 1) {
                Stop-AskBridgeParentForUpdate
            }

            if ($attempt -eq 10) {
                throw
            }

            Write-Host "Retrying copy for $Destination in 500ms (attempt $attempt/10)..." -ForegroundColor Yellow
            Start-Sleep -Milliseconds 500
        }
    }
}

function Assert-WindowsExecutable {
    param(
        [Parameter(Mandatory)] [string] $Path
    )

    $stream = [System.IO.File]::OpenRead($Path)
    try {
        $firstByte = $stream.ReadByte()
        $secondByte = $stream.ReadByte()
    } finally {
        $stream.Dispose()
    }

    if ($firstByte -ne 0x4D -or $secondByte -ne 0x5A) {
        throw "Binary '$Path' is not a Windows PE executable (missing MZ header). Refusing to install a mismatched platform artifact."
    }
}

# Compare the downloaded archive against the SHA-256 the release workflow
# published beside it (release.yml, "Package binary" -> "$archive.sha256" --
# that step runs for every target, so the Windows .zip has one too).
#
# This is the Windows half of the guarantee `verify_release_checksum` in
# install.sh gives on macOS/Linux. `ask-bridge update` runs one installer or the
# other unattended and both overwrite the binary the user then runs, so neither
# path may install "whatever the download produced": a mirror, a caching proxy
# or a truncated body would land and be reported as a success. Until 2026-08-14
# this script had no checksum check of any kind while install.sh did, so the
# security claim covered exactly one of the two supported platforms.
#
# Fails closed by construction: the expected digest must be 64 hex characters
# *before* it is compared to anything, so an empty checksum file, a truncated
# digest, or a "404: Not Found" page saved where the checksum should be throws
# rather than being read as agreement. ("" -eq "" is the one way two unknowns
# compare equal, which is the bug the format guard exists to prevent.)
#
# Not a new design: this is `verifyChecksum` from npm/postinstall.cjs, step for
# step -- trim, split on whitespace, take the first field, lower-case it, reject
# anything that is not /^[a-f0-9]{64}$/, then compare. That path has verified
# this same archive since before either shell installer did, so the three
# installers now agree rather than each inventing a rule.
#
# What it is NOT -- stated here so the Windows path does not inherit a
# stronger-sounding claim than it has, the same limitation install.sh states:
# the checksum comes from the same host, over the same connection, as the
# archive it describes. It catches a body that changed on the way here --
# corruption, truncation, a stale mirror, a caching proxy -- and nothing more.
# Anyone who can serve the archive can serve a matching .sha256, so this is not
# a defence against a compromised release host or a broken TLS path; that needs
# a signature checkable against a key the installer did not just download, which
# upstream does not publish. It also says nothing about *this script*, which
# `ask-bridge update` still fetches with `irm ... | iex`; see
# `known_gap_the_windows_updater_pipes_the_installer_into_powershell` in
# tests/installer_integrity.rs.
#
# What TESTS this, and what they cannot see: `install_ps1_verifies_the_
# published_checksum_before_it_extracts` and `install_ps1_checksum_gate_refuses_
# instead_of_warning` (tests/installer_integrity.rs) read this file as text.
# install.sh's equivalent has more than that -- an offline end-to-end run that
# executes the installer and looks at the bytes on disk -- and this path does
# not, because there is no PowerShell on the machine this was written on, so an
# executable Windows test could only have been shipped unrun. The consequence is
# specific and worth stating rather than hedging: a mutation that keeps the text
# and disables the effect -- `if ($false -and $actual -ne $expected)` -- passes
# every assertion those two tests make. Closing it needs a Windows runner step
# that runs `Assert-ReleaseChecksum` against a matching and a mismatching file.
function Assert-ReleaseChecksum {
    param(
        [Parameter(Mandatory)] [string] $Archive,
        [Parameter(Mandatory)] [string] $ChecksumPath
    )

    $checksumText = Get-Content -Path $ChecksumPath -Raw -ErrorAction Stop
    $expected = ""
    if ($checksumText) {
        $expected = ($checksumText.Trim() -split '\s+')[0].ToLowerInvariant()
    }
    if ($expected -notmatch '^[a-f0-9]{64}$') {
        throw "Checksum file '$ChecksumPath' does not contain a SHA-256 digest. Refusing to install '$Archive'."
    }

    $actual = (Get-FileHash -Path $Archive -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    if ($actual -ne $expected) {
        throw "SHA-256 verification failed for '$Archive': expected $expected, got $actual. Refusing to install."
    }
}

function Confirm-AskBridgeBinary {
    param(
        [Parameter(Mandatory)] [string] $Path
    )

    Assert-WindowsExecutable -Path $Path
    try {
        $versionOutput = & $Path --version 2>&1
        $versionExitCode = $LASTEXITCODE
    } catch {
        throw "Installed ask-bridge binary could not start: $($_.Exception.Message)"
    }
    $versionText = ($versionOutput | Out-String).Trim()
    if ($versionExitCode -ne 0) {
        throw "Installed ask-bridge binary failed its version check with exit code $versionExitCode`: $versionText"
    }
    if ($versionText -notmatch '^ask-bridge\s+\d+\.\d+\.\d+') {
        throw "Installed ask-bridge binary returned unexpected version output: '$versionText'"
    }
}

function Set-AskBridgePathPriority {
    param(
        [Parameter(Mandatory)] [string] $InstallDir
    )

    $installKey = $InstallDir.Trim().TrimEnd([char[]]"\/")
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $userEntries = @(
        $userPath -split ';' |
            Where-Object {
                $_ -and $_.Trim().TrimEnd([char[]]"\/") -ine $installKey
            }
    )
    $newUserPath = (@($InstallDir) + $userEntries) -join ';'
    [Environment]::SetEnvironmentVariable("Path", $newUserPath, "User")

    $processEntries = @(
        $env:Path -split ';' |
            Where-Object {
                $_ -and $_.Trim().TrimEnd([char[]]"\/") -ine $installKey
            }
    )
    $env:Path = (@($InstallDir) + $processEntries) -join ';'
}

function Confirm-AskBridgeCommandResolution {
    param(
        [Parameter(Mandatory)] [string] $ExpectedPath
    )

    $resolved = Get-Command ask-bridge.exe -CommandType Application -ErrorAction Stop |
        Select-Object -First 1
    $resolvedPath = [System.IO.Path]::GetFullPath($resolved.Source)
    $expectedFullPath = [System.IO.Path]::GetFullPath($ExpectedPath)
    if ($resolvedPath -ine $expectedFullPath) {
        throw "The 'ask-bridge.exe' command resolves to '$resolvedPath' instead of the newly installed '$expectedFullPath'."
    }
}

# 1. Check Node.js and npx
$nodeCheck = Get-Command node -ErrorAction SilentlyContinue
$npxCheck = Get-Command npx -ErrorAction SilentlyContinue

if (-not $nodeCheck) {
    Write-Error "Node.js is not installed. Please install Node.js (https://nodejs.org/) and retry."
    exit 1
}

if (-not $npxCheck) {
    Write-Error "npx is not installed. Please ensure NPM/npx is available in your PATH."
    exit 1
}

$nodeVersionOutput = & node --version 2>&1
$nodeVersionExitCode = $LASTEXITCODE
$nodeVersionText = ($nodeVersionOutput | Out-String).Trim()

if ($nodeVersionExitCode -ne 0 -or $nodeVersionText -notmatch '^v?(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$') {
    Write-Error "Could not determine a supported Node.js version. Install a current Node.js LTS release, reopen PowerShell, and retry."
    exit 1
}

$nodeMajor = [int]$Matches[1]
$nodeMinor = [int]$Matches[2]
$nodePatch = [int]$Matches[3]
$nodeVersionSupported = `
    ($nodeMajor -eq 20 -and ($nodeMinor -gt 19 -or ($nodeMinor -eq 19 -and $nodePatch -ge 0))) -or `
    ($nodeMajor -eq 22 -and ($nodeMinor -gt 12 -or ($nodeMinor -eq 12 -and $nodePatch -ge 0))) -or `
    ($nodeMajor -ge 23)

if (-not $nodeVersionSupported) {
    Write-Error "Node.js $nodeVersionText is not supported by chrome-devtools-mcp@latest. Supported versions are ^20.19.0, ^22.12.0, or >=23.0.0. Install a current Node.js LTS release, reopen PowerShell, and retry."
    exit 1
}

# 2. Check Google Chrome
$chromePaths = @(
    "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
    "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
    "$env:LocalAppData\Google\Chrome\Application\chrome.exe"
)

$chromeFound = $false
foreach ($path in $chromePaths) {
    if (Test-Path $path) {
        $chromeFound = $true
        break
    }
}

if (-not $chromeFound) {
    Write-Host "Warning: Google Chrome was not found in default installation paths." -ForegroundColor Yellow
    Write-Host "Please ensure Google Chrome is installed, as it is required by Chrome DevTools MCP." -ForegroundColor Yellow
}

# 3. Install from local build (for development)
if ($Local) {
    $LocalRoot = if ($MyInvocation.MyCommand.Path) {
        Split-Path -Parent $MyInvocation.MyCommand.Path
    } else {
        Get-Location
    }

    if ([string]::IsNullOrWhiteSpace($LocalPath)) {
        $LocalPath = Join-Path $LocalRoot "target\release\ask-bridge.exe"
        $LocalUpdatePath = Join-Path $LocalRoot "target\release\ask-bridge-update.exe"
    } else {
        $LocalPath = [System.IO.Path]::GetFullPath($LocalPath)
        $LocalUpdatePath = Join-Path (Split-Path $LocalPath) "ask-bridge-update.exe"
    }

    $LocalPathDir = Split-Path $LocalPath
    if (-not (Test-Path $LocalPathDir)) {
        try {
            $null = New-Item -ItemType Directory -Force -Path $LocalPathDir
        } catch {
            Write-Error "Failed to prepare local build directory '$LocalPathDir'."
            exit 1
        }
    }

    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        Write-Error "Rust toolchain not found. Please install Rust and retry."
        exit 1
    }

    Write-Host "Building ask-bridge in release mode..." -ForegroundColor Cyan
    try {
        Push-Location $LocalRoot
        & cargo build --release
        if ($LASTEXITCODE -ne 0) {
            Write-Error "cargo build --release failed. Exit code: $LASTEXITCODE"
            exit 1
        }
    } finally {
        Pop-Location
    }

    if (-not (Test-Path $LocalPath)) {
        Write-Error "Local binary not found at '$LocalPath' even after cargo build. Check repository permissions and build output path."
        exit 1
    }
    if (-not (Test-Path $LocalUpdatePath)) {
        Write-Error "Local updater binary not found at '$LocalUpdatePath'. Check repository permissions and build output path."
        exit 1
    }
    Assert-WindowsExecutable -Path $LocalPath
    Assert-WindowsExecutable -Path $LocalUpdatePath

    $InstallDir = Join-Path $HOME ".local\bin"
    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    }

    $DestPath = Join-Path $InstallDir "ask-bridge.exe"
    $AliasPath = Join-Path $InstallDir "ask.exe"
    $UpdatePath = Join-Path $InstallDir "ask-bridge-update.exe"
    Write-Host "Installing local ask-bridge.exe to $InstallDir..." -ForegroundColor Cyan
    $ResolvedLocalPath = (Resolve-Path $LocalPath).Path
    $ResolvedLocalUpdatePath = (Resolve-Path $LocalUpdatePath).Path
    Copy-ItemWithRetry -Source $ResolvedLocalPath -Destination $DestPath
    Copy-ItemWithRetry -Source $ResolvedLocalPath -Destination $AliasPath
    Copy-ItemWithRetry -Source $ResolvedLocalUpdatePath -Destination $UpdatePath

    Confirm-AskBridgeBinary -Path $DestPath
    Write-Host "Putting $InstallDir first in User PATH..." -ForegroundColor Cyan
    Set-AskBridgePathPriority -InstallDir $InstallDir
    Confirm-AskBridgeCommandResolution -ExpectedPath $DestPath

    Write-Host "Successfully installed! You can now use the 'ask-bridge' command. The 'ask' alias is also available." -ForegroundColor Green
    exit 0
}

# 3. Target configuration
$Version = "0.2.10"
$RepoOwner = "doggy8088"
$RepoName = "ask-bridge"
$ArtifactName = "ask-bridge-x86_64-pc-windows-msvc.zip"
$ReleaseUrl = "https://github.com/$RepoOwner/$RepoName/releases/download/v$Version/$ArtifactName"

# 4. Create installation directory
$InstallDir = Join-Path $HOME ".local\bin"
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
}

$TempDir = Join-Path $env:TEMP "ask-bridge-install"
if (Test-Path $TempDir) {
    Remove-Item -Recurse -Force $TempDir
}
New-Item -ItemType Directory -Path $TempDir | Out-Null

try {
    # 5. Download zip and the checksum published beside it
    Write-Host "Downloading $ArtifactName..." -ForegroundColor Cyan
    $ZipPath = Join-Path $TempDir $ArtifactName
    $ChecksumPath = "${ZipPath}.sha256"
    Invoke-WebRequest -Uri $ReleaseUrl -OutFile $ZipPath
    Invoke-WebRequest -Uri "${ReleaseUrl}.sha256" -OutFile $ChecksumPath

    # 6. Verify before extracting. Refusing after Expand-Archive has run and the
    # binaries have been copied over $InstallDir is too late to be a refusal.
    Write-Host "Verifying SHA-256 checksum..." -ForegroundColor Cyan
    Assert-ReleaseChecksum -Archive $ZipPath -ChecksumPath $ChecksumPath

    # 7. Extract zip
    Write-Host "Extracting archive..." -ForegroundColor Cyan
    Expand-Archive -Path $ZipPath -DestinationPath $TempDir -Force

    # Find the executable
    $ExePath = Get-ChildItem -Path $TempDir -Recurse -Filter "ask-bridge.exe" | Select-Object -First 1
    if (-not $ExePath) {
        Write-Error "Could not find ask-bridge.exe in the downloaded archive."
        exit 1
    }
    $UpdateExePath = Get-ChildItem -Path $TempDir -Recurse -Filter "ask-bridge-update.exe" | Select-Object -First 1
    Assert-WindowsExecutable -Path $ExePath.FullName
    if ($UpdateExePath) {
        Assert-WindowsExecutable -Path $UpdateExePath.FullName
    }

    # Copy to destination as ask-bridge.exe and keep ask.exe as an alias.
    $DestPath = Join-Path $InstallDir "ask-bridge.exe"
    $AliasPath = Join-Path $InstallDir "ask.exe"
    $UpdateDestPath = Join-Path $InstallDir "ask-bridge-update.exe"
    Write-Host "Installing ask-bridge.exe to $InstallDir..." -ForegroundColor Cyan
    Copy-ItemWithRetry -Source $ExePath.FullName -Destination $DestPath
    Copy-ItemWithRetry -Source $ExePath.FullName -Destination $AliasPath

    if ($UpdateExePath) {
        Write-Host "Installing ask-bridge-update.exe to $InstallDir..." -ForegroundColor Cyan
        Copy-ItemWithRetry -Source $UpdateExePath.FullName -Destination $UpdateDestPath
    } else {
        Write-Host "Warning: ask-bridge-update.exe not found in archive; update helper unavailable." -ForegroundColor Yellow
    }
    Confirm-AskBridgeBinary -Path $DestPath
}
finally {
    # Clean up temp
    if (Test-Path $TempDir) {
        Remove-Item -Recurse -Force $TempDir
    }
}

# 8. Put the verified installation first in PATH and ensure command resolution.
Write-Host "Putting $InstallDir first in User PATH..." -ForegroundColor Cyan
Set-AskBridgePathPriority -InstallDir $InstallDir
Confirm-AskBridgeCommandResolution -ExpectedPath $DestPath

Write-Host "Successfully installed! You can now use the 'ask-bridge' command. The 'ask' alias is also available." -ForegroundColor Green
