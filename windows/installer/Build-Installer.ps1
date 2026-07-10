# ============================================================================
#  Build-Installer.ps1  -  one command to produce a (optionally signed) setup
#
#  Pipeline:
#    1. (optional) build the native launcher exe and sign it
#    2. compile the Inno Setup installer (ISCC)
#    3. (optional) sign the produced installer
#
#  Examples
#    # Unsigned build (for local testing only - will show SmartScreen warnings):
#    .\Build-Installer.ps1
#
#    # Signed build with a token certificate:
#    .\Build-Installer.ps1 -Sign -Thumbprint 'AB12...CD'
#
#    # Signed build via Trusted Signing (cloud, no token):
#    .\Build-Installer.ps1 -Sign -TrustedSigning -Metadata .\trusted-signing.json
#
#    # Also build + ship the signed native launcher .exe:
#    .\Build-Installer.ps1 -WithLauncher -Sign -Thumbprint 'AB12...CD'
# ============================================================================
[CmdletBinding()]
param(
    [switch] $Sign,
    [switch] $WithLauncher,
    [string] $Thumbprint,
    [switch] $TrustedSigning,
    [string] $Metadata,
    [string] $ISCC = 'iscc.exe'
)
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$root = Split-Path $here -Parent

function Invoke-Sign {
    param([string[]] $Files)
    if (-not $Sign) { return }
    $args = @{ File = $Files }
    if ($TrustedSigning) { $args.TrustedSigning = $true; $args.Metadata = $Metadata }
    else                 { $args.Thumbprint = $Thumbprint }
    & (Join-Path $here 'sign.ps1') @args
}

# 1) Optional native launcher ------------------------------------------------
if ($WithLauncher) {
    Write-Host '== Building native launcher exe ==' -ForegroundColor Cyan
    & (Join-Path $root 'build\Build-Exe.ps1')
    $exe = Join-Path $root 'StrixDiskCleaner.exe'
    if (-not (Test-Path $exe)) { throw 'Launcher build did not produce StrixDiskCleaner.exe' }
    Invoke-Sign -Files @($exe)
    Write-Warning 'Remember: enable the signed-launcher lines in StrixDiskCleaner.iss to ship it.'
}

# 2) Compile the installer ---------------------------------------------------
Write-Host '== Compiling installer (ISCC) ==' -ForegroundColor Cyan
$iss = Join-Path $here 'StrixDiskCleaner.iss'
$isccCmd = Get-Command $ISCC -ErrorAction SilentlyContinue
$iscc = if ($isccCmd) { $isccCmd.Source } else { $null }
if (-not $iscc) {
    foreach ($p in @("${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
                     "${env:ProgramFiles}\Inno Setup 6\ISCC.exe")) {
        if (Test-Path $p) { $iscc = $p; break }
    }
}
if (-not $iscc) { throw 'ISCC.exe not found. Install Inno Setup 6 (https://jrsoftware.org/isdl.php).' }
& $iscc $iss
if ($LASTEXITCODE -ne 0) { throw "ISCC failed (exit $LASTEXITCODE)" }

$setup = Get-ChildItem (Join-Path $here 'dist') -Filter 'StrixDiskCleaner-Setup-*.exe' |
         Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $setup) { throw 'Installer was not produced.' }
Write-Host "Installer: $($setup.FullName)"

# 3) Sign the installer ------------------------------------------------------
Invoke-Sign -Files @($setup.FullName)

Write-Host "`nDone." -ForegroundColor Green
if (-not $Sign) {
    Write-Warning 'This build is UNSIGNED. Windows will show a SmartScreen "unknown publisher" warning and it remains false-positive-prone. Sign it before distributing (see README-PACKAGING.md).'
}
