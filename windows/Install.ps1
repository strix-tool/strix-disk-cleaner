# Installs Strix Disk Cleaner for the current user and creates Desktop +
# Start Menu shortcuts with the application icon.
#
# This installer ships NO packaged .exe. It copies the PowerShell application
# and points the shortcuts at Windows PowerShell directly, so nothing on disk
# has the "embedded-script launcher" shape that made Defender's ML classifier
# raise a Trojan:Win32/Wacatac.B!ml false positive on the old .exe build.
$ErrorActionPreference = 'Stop'

$ps1Src = Join-Path $PSScriptRoot 'StrixDiskCleaner.ps1'
$icoSrc = Join-Path $PSScriptRoot 'app.ico'
if (-not (Test-Path $ps1Src)) { throw "StrixDiskCleaner.ps1 not found next to this script." }

$dest = Join-Path $env:LOCALAPPDATA 'Programs\Strix Disk Cleaner'
New-Item -ItemType Directory -Force -Path $dest | Out-Null
Copy-Item $ps1Src (Join-Path $dest 'StrixDiskCleaner.ps1') -Force
if (Test-Path $icoSrc) { Copy-Item $icoSrc (Join-Path $dest 'app.ico') -Force }

$ps1  = Join-Path $dest 'StrixDiskCleaner.ps1'
$ico  = Join-Path $dest 'app.ico'
# Absolute path to Windows PowerShell (never trust PATH for a shortcut target).
$pwsh = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'

$ws = New-Object -ComObject WScript.Shell
foreach ($folder in @([Environment]::GetFolderPath('Desktop'),
                      [Environment]::GetFolderPath('Programs'))) {
    $s = $ws.CreateShortcut((Join-Path $folder 'Strix Disk Cleaner.lnk'))
    $s.TargetPath       = $pwsh
    $s.Arguments        = "-NoProfile -ExecutionPolicy Bypass -File `"$ps1`""
    $s.WorkingDirectory = $dest
    if (Test-Path $ico) { $s.IconLocation = "$ico,0" }
    $s.WindowStyle      = 7   # start minimized: no lingering console (GUI takes over)
    $s.Description      = 'Strix Disk Cleaner - Professional Data Destruction Tool'
    $s.Save()
}

Write-Host 'Installed (script-based, no packaged .exe).'
Write-Host "Application folder : $dest"
Write-Host 'Shortcuts created on the Desktop and in the Start Menu.'
Write-Host 'The application asks for Administrator rights when launched.'
