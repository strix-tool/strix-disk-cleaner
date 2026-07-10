build/ - the no-console launcher
================================

Launcher.cs        minimal native launcher source. GUI subsystem (no console),
                   requireAdministrator manifest, starts the installed
                   StrixDiskCleaner.ps1 with CreateNoWindow. It does NOT embed
                   or extract any payload - that "drop + hidden shell" shape is
                   what tripped Defender on the old build.
Build-Launcher.ps1 compiles Launcher.cs with csc (ships with .NET Framework on
                   Windows 10/11) -> StrixDiskCleaner.exe
app.manifest       requireAdministrator manifest embedded into the launcher
app.ico            application icon embedded into the launcher
StrixDiskCleaner.exe  a prebuilt launcher (convenience). For a production build,
                   recompile with Build-Launcher.ps1 on Windows and SIGN it.

Sign the launcher (installer\sign.ps1) before packaging for a warning-free
install. See installer\README-PACKAGING.md.
