# ============================================================================
#  Build-Launcher.ps1  -  compile the no-console launcher on Windows (native)
#
#  Uses the C# compiler that ships with the .NET Framework on every Windows
#  10/11 machine (no SDK needed). Produces ..\build\StrixDiskCleaner.exe:
#    - GUI subsystem (target:winexe)  -> the launcher has no console
#    - app.manifest (requireAdministrator) -> single clean UAC prompt
#    - app.ico embedded
#  The launcher then starts the installed StrixDiskCleaner.ps1 with
#  CreateNoWindow, so no console appears at any stage.
#
#  Sign it afterwards (installer\sign.ps1) for a warning-free install.
# ============================================================================
$ErrorActionPreference = 'Stop'
$build = $PSScriptRoot
$out   = Join-Path $build 'StrixDiskCleaner.exe'
$src   = Join-Path $build 'Launcher.cs'

$csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path $csc)) { $csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe' }
if (-not (Test-Path $csc)) { throw 'csc.exe not found - .NET Framework 4.x is required (ships with Windows 10/11).' }

& $csc /nologo /target:winexe /platform:anycpu /optimize+ `
    /win32icon:"$build\app.ico" `
    /win32manifest:"$build\app.manifest" `
    /out:"$out" "$src"

if (-not (Test-Path $out)) { throw 'Launcher build failed.' }
Write-Host "OK -> $out"
Write-Host 'Next: sign it, then build the installer (installer\Build-Setup.ps1).'
