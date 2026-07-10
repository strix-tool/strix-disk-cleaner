# Rebuilds StrixDiskCleaner.exe from ..\StrixDiskCleaner.ps1 (run on Windows).
# Embeds the script, its SHA-256 fingerprint, the application icon and the
# requireAdministrator manifest. No SDK needed - uses the C# compiler that
# ships with the .NET Framework on every Windows 10/11 machine.
$ErrorActionPreference = 'Stop'
$build = $PSScriptRoot
$root  = Split-Path $build -Parent
$ps1   = Join-Path $root 'StrixDiskCleaner.ps1'
if (-not (Test-Path $ps1)) { throw "Not found: $ps1" }

$hash = (Get-FileHash $ps1 -Algorithm SHA256).Hash.ToLower()
$cs   = (Get-Content (Join-Path $build 'Launcher.cs') -Raw).Replace('%HASH%', $hash)
$tmp  = Join-Path $env:TEMP 'SDC_Launcher.cs'
Set-Content -Path $tmp -Value $cs -Encoding UTF8

$csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path $csc)) { $csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe' }
if (-not (Test-Path $csc)) { throw 'C# compiler (csc.exe) not found - .NET Framework 4.x is required.' }

& $csc /nologo /target:winexe /platform:anycpu /optimize+ `
    /win32icon:"$build\app.ico" `
    /win32manifest:"$build\app.manifest" `
    /resource:"$ps1",app.ps1 `
    /out:"$root\StrixDiskCleaner.exe" "$tmp"
Remove-Item $tmp -Force

Write-Host "OK -> $root\StrixDiskCleaner.exe"
Write-Host "Embedded script SHA-256: $hash"
