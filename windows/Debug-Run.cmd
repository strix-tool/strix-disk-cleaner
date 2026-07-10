@echo off
REM Strix Disk Cleaner - diagnostic mode
REM If the app does not open, run this file AS ADMINISTRATOR;
REM PowerShell errors stay VISIBLE in this window.
echo ============================================================
echo   Strix Disk Cleaner - Diagnostic / Debug Run
echo   (Run this AS ADMINISTRATOR if the app won't start)
echo ============================================================
echo.
"%WINDIR%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0StrixDiskCleaner.ps1"
echo.
echo ============================================================
echo   Script exited. If you saw a red error above, copy it.
echo   A copy may also be at: %TEMP%\StrixDiskCleaner_error.log
echo ============================================================
pause
