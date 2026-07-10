' Strix Disk Cleaner - silent, elevated launcher.
' Elevates ONCE via a single UAC prompt (the correct consent boundary for a
' destructive disk eraser) with NO PowerShell console window flashing:
' wscript is windowless, and ShellExecute with nShow=0 (SW_HIDE) + "runas"
' hides the console and elevates in one step, so the .ps1's own self-elevation
' branch is skipped (no second PowerShell, no double prompt).
Option Explicit
Dim here, ps
here = Left(WScript.ScriptFullName, InStrRev(WScript.ScriptFullName, "\"))
' Absolute System32 path (anti PATH-hijack), matching the .ps1's own policy.
ps = CreateObject("WScript.Shell").ExpandEnvironmentStrings("%SystemRoot%") & _
     "\System32\WindowsPowerShell\v1.0\powershell.exe"
CreateObject("Shell.Application").ShellExecute ps, _
  "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File """ & _
  here & "StrixDiskCleaner.ps1""", here, "runas", 0
