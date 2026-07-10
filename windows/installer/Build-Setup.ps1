# ============================================================================
#  Build-Setup.ps1  -  build the next-next-next wizard installer on Windows
#
#  Pipeline:
#    1. (re)build the no-console launcher  (build\Build-Launcher.ps1)
#    2. (optional) sign the launcher
#    3. compile the NSIS wizard installer  -> installer\dist\StrixDiskCleaner-Setup-<ver>.exe
#    4. (optional) sign the installer
#
#  Prereqs on the Windows build machine:
#    - NSIS 3.x            https://nsis.sourceforge.io/Download   (provides makensis.exe)
#    - .NET Framework 4.x  (ships with Windows; provides csc.exe)
#    - Windows SDK         only if signing (provides signtool.exe)
#
#  Examples:
#    .\Build-Setup.ps1                                   # unsigned (testing)
#    .\Build-Setup.ps1 -Sign -Thumbprint 'AB12...CD'     # signed (token cert)
#    .\Build-Setup.ps1 -Sign -TrustedSigning -Metadata .\trusted-signing.json
# ============================================================================
[CmdletBinding()]
param(
    [switch] $Sign,
    [string] $Thumbprint,
    [switch] $TrustedSigning,
    [string] $Metadata,
    [string] $MakeNSIS = 'makensis.exe'
)
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$root = Split-Path $here -Parent

function Invoke-Sign {
    param([string[]] $Files)
    if (-not $Sign) { return }
    $a = @{ File = $Files }
    if ($TrustedSigning) { $a.TrustedSigning = $true; $a.Metadata = $Metadata } else { $a.Thumbprint = $Thumbprint }
    & (Join-Path $here 'sign.ps1') @a
}

# 1) launcher ----------------------------------------------------------------
Write-Host '== Building no-console launcher ==' -ForegroundColor Cyan
& (Join-Path $root 'build\Build-Launcher.ps1')
$launcher = Join-Path $root 'build\StrixDiskCleaner.exe'
if (-not (Test-Path $launcher)) { throw 'launcher not built' }

# 2) sign launcher (before it is packed into the installer) ------------------
Invoke-Sign -Files @($launcher)

# 3) compile the NSIS installer ---------------------------------------------
Write-Host '== Compiling wizard installer (makensis) ==' -ForegroundColor Cyan
$makensisCmd = Get-Command $MakeNSIS -ErrorAction SilentlyContinue
$makensis = if ($makensisCmd) { $makensisCmd.Source } else { $null }
if (-not $makensis) {
    foreach ($p in @("${env:ProgramFiles(x86)}\NSIS\makensis.exe",
                     "${env:ProgramFiles}\NSIS\makensis.exe")) {
        if (Test-Path $p) { $makensis = $p; break }
    }
}
if (-not $makensis) { throw 'makensis.exe not found. Install NSIS 3.x (https://nsis.sourceforge.io/Download).' }

New-Item -ItemType Directory -Force -Path (Join-Path $here 'dist') | Out-Null
& $makensis (Join-Path $here 'StrixDiskCleaner.nsi')
if ($LASTEXITCODE -ne 0) { throw "makensis failed (exit $LASTEXITCODE)" }

$setup = Get-ChildItem (Join-Path $here 'dist') -Filter 'StrixDiskCleaner-Setup-*.exe' |
         Sort-Object LastWriteTime -Descending | Select-Object -First 1
Write-Host "Installer: $($setup.FullName)"

# 4) sign the installer ------------------------------------------------------
Invoke-Sign -Files @($setup.FullName)

Write-Host "`nDone." -ForegroundColor Green
if (-not $Sign) {
    Write-Warning 'UNSIGNED build: Windows SmartScreen will show an "unknown publisher" warning. Sign it before distributing (see README-PACKAGING.md).'
}
