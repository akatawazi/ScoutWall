# Installs ScoutWall on Windows. Run in an administrator PowerShell:
#   irm https://github.com/__REPOSITORY__/releases/download/v__VERSION__/install.ps1 | iex
# This script is attached to one release and installs exactly that release. It downloads scoutwall.exe, checks
# its SHA-256 checksum against the release's SHA256SUMS file, then runs "scoutwall install".

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$repository = "__REPOSITORY__"
$version = "__VERSION__"
$asset = "scoutwall-win-x64.exe"
$base = "https://github.com/$repository/releases/download/v$version"

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Please run this in an administrator PowerShell (right-click PowerShell or Terminal, 'Run as administrator')." -ForegroundColor Yellow
    return
}

$folder = Join-Path ([IO.Path]::GetTempPath()) "scoutwall-install-$version"
New-Item -ItemType Directory -Force -Path $folder | Out-Null
$executable = Join-Path $folder "scoutwall.exe"
$sums = Join-Path $folder "SHA256SUMS"

Write-Host "Downloading ScoutWall $version..."
Invoke-WebRequest "$base/$asset" -OutFile $executable -UseBasicParsing
Invoke-WebRequest "$base/SHA256SUMS" -OutFile $sums -UseBasicParsing

$expected = (Get-Content $sums | Where-Object { $_ -match [regex]::Escape($asset) } | ForEach-Object { ($_ -split '\s+')[0] }) | Select-Object -First 1
$actual = (Get-FileHash $executable -Algorithm SHA256).Hash.ToLowerInvariant()
if (-not $expected -or $actual -ne $expected.ToLowerInvariant()) {
    Remove-Item $executable -Force
    throw "The download didn't match its checksum; nothing was installed. Try again, or download it yourself from https://github.com/$repository/releases."
}

& $executable install
if ($LASTEXITCODE -eq 0) {
    Start-Process "http://localhost:5215"
}
