; ============================================================================
;  Strix Disk Cleaner - NSIS installer (next-next-next wizard)
;  Produces StrixDiskCleaner-Setup-<ver>.exe: a normal Windows setup wizard.
;    - Welcome / Directory / Install / Finish pages
;    - installs the no-console launcher + the PowerShell app + icon
;    - Start Menu + Desktop shortcuts point at the launcher (no console window)
;    - registers in "Apps & features" with a proper uninstaller
;  Built with makensis (cross-platform). See build note in README-PACKAGING.md.
; ============================================================================

Unicode true
!include "MUI2.nsh"

!define APPNAME     "Strix Disk Cleaner"
!define APPVERSION  "2.3.0"
!define PUBLISHER   "Strix"
!define APPEXE      "StrixDiskCleaner.exe"
!define REGKEY      "Software\Microsoft\Windows\CurrentVersion\Uninstall\StrixDiskCleaner"

Name "${APPNAME}"
OutFile "dist\StrixDiskCleaner-Setup-${APPVERSION}.exe"
InstallDir "$PROGRAMFILES64\${APPNAME}"
InstallDirRegKey HKLM "Software\${APPNAME}" "InstallDir"
RequestExecutionLevel admin          ; setup needs admin to write Program Files
SetCompressor /SOLID lzma
BrandingText "${APPNAME} ${APPVERSION}"

; ---- Wizard UI -------------------------------------------------------------
!define MUI_ICON   "..\app.ico"
!define MUI_UNICON "..\app.ico"
!define MUI_ABORTWARNING
!define MUI_FINISHPAGE_RUN "$INSTDIR\${APPEXE}"
!define MUI_FINISHPAGE_RUN_TEXT "Launch ${APPNAME}"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

; ---- Install ---------------------------------------------------------------
Section "Install"
    SetOutPath "$INSTDIR"
    SetOverwrite on

    File "..\StrixDiskCleaner.ps1"
    File "..\build\StrixDiskCleaner.exe"          ; the no-console launcher
    File "..\app.ico"
    File "..\README-WINDOWS.md"

    ; Start Menu + Desktop shortcuts -> the launcher (own icon, no console)
    CreateDirectory "$SMPROGRAMS\${APPNAME}"
    CreateShortCut  "$SMPROGRAMS\${APPNAME}\${APPNAME}.lnk" \
        "$INSTDIR\${APPEXE}" "" "$INSTDIR\app.ico" 0
    CreateShortCut  "$SMPROGRAMS\${APPNAME}\Uninstall ${APPNAME}.lnk" \
        "$INSTDIR\uninstall.exe"
    CreateShortCut  "$DESKTOP\${APPNAME}.lnk" \
        "$INSTDIR\${APPEXE}" "" "$INSTDIR\app.ico" 0

    ; Remember install dir
    WriteRegStr HKLM "Software\${APPNAME}" "InstallDir" "$INSTDIR"

    ; Add/Remove Programs entry
    WriteRegStr   HKLM "${REGKEY}" "DisplayName"     "${APPNAME}"
    WriteRegStr   HKLM "${REGKEY}" "DisplayVersion"  "${APPVERSION}"
    WriteRegStr   HKLM "${REGKEY}" "Publisher"       "${PUBLISHER}"
    WriteRegStr   HKLM "${REGKEY}" "DisplayIcon"     "$INSTDIR\app.ico"
    WriteRegStr   HKLM "${REGKEY}" "UninstallString" "$INSTDIR\uninstall.exe"
    WriteRegStr   HKLM "${REGKEY}" "InstallLocation" "$INSTDIR"
    WriteRegDWORD HKLM "${REGKEY}" "NoModify" 1
    WriteRegDWORD HKLM "${REGKEY}" "NoRepair" 1

    WriteUninstaller "$INSTDIR\uninstall.exe"
SectionEnd

; ---- Uninstall -------------------------------------------------------------
Section "Uninstall"
    Delete "$INSTDIR\StrixDiskCleaner.ps1"
    Delete "$INSTDIR\${APPEXE}"
    Delete "$INSTDIR\app.ico"
    Delete "$INSTDIR\README-WINDOWS.md"
    Delete "$INSTDIR\uninstall.exe"
    RMDir  "$INSTDIR"

    Delete "$SMPROGRAMS\${APPNAME}\${APPNAME}.lnk"
    Delete "$SMPROGRAMS\${APPNAME}\Uninstall ${APPNAME}.lnk"
    RMDir  "$SMPROGRAMS\${APPNAME}"
    Delete "$DESKTOP\${APPNAME}.lnk"

    ; old per-user runtime copy from the pre-2.3 launcher, if present
    RMDir /r "$LOCALAPPDATA\StrixDiskCleaner\app"

    DeleteRegKey HKLM "${REGKEY}"
    DeleteRegKey HKLM "Software\${APPNAME}"

    ; Offer to remove saved settings
    MessageBox MB_YESNO|MB_ICONQUESTION \
        "Also remove saved settings (theme, language, report folder)?" \
        IDNO skipSettings
        RMDir /r "$APPDATA\StrixDiskCleaner"
    skipSettings:
SectionEnd
