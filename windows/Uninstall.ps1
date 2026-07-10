# Removes Strix Disk Cleaner, its shortcuts and (optionally) its settings.
$ErrorActionPreference = 'SilentlyContinue'
Remove-Item (Join-Path ([Environment]::GetFolderPath('Desktop'))  'Strix Disk Cleaner.lnk') -Force
Remove-Item (Join-Path ([Environment]::GetFolderPath('Programs')) 'Strix Disk Cleaner.lnk') -Force
Remove-Item (Join-Path $env:LOCALAPPDATA 'Programs\Strix Disk Cleaner') -Recurse -Force
Remove-Item (Join-Path $env:LOCALAPPDATA 'StrixDiskCleaner') -Recurse -Force   # old .exe extracted-app copy, if any
$answer = Read-Host 'Also remove saved settings (settings.json)? [y/N]'
if ($answer -match '^[yY]') { Remove-Item (Join-Path $env:APPDATA 'StrixDiskCleaner') -Recurse -Force }
Write-Host 'Uninstalled.'
