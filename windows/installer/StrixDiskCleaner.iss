; ============================================================================
;  Strix Disk Cleaner - Inno Setup installer script
;  Produces a professional Windows installer:
;    - installs to Program Files
;    - Start Menu + optional Desktop shortcut (with the app icon)
;    - registers in "Apps & features" (Add/Remove Programs) with a clean
;      uninstaller, publisher name, version and icon
;
;  Default launch path is SCRIPT-BASED (a shortcut to Windows PowerShell running
;  StrixDiskCleaner.ps1). That avoids shipping an opaque, embedded-payload .exe -
;  the thing that triggered the Defender false positive. See the [Icons] section
;  for the optional signed-launcher variant.
;
;  Build:   iscc StrixDiskCleaner.iss          (Inno Setup 6+)
;  Sign:    handled by Build-Installer.ps1 (signs the produced setup .exe)
; ============================================================================

#define AppName        "Strix Disk Cleaner"
#define AppVersion     "2.3.0"
#define AppPublisher   "Strix"
#define AppURL         "https://example.invalid/strix"
; Absolute path to Windows PowerShell (script launch target)
#define PwshExe        "{sys}\WindowsPowerShell\v1.0\powershell.exe"

[Setup]
; A stable, unique AppId keeps upgrades/uninstall correct across versions.
; Generate ONE GUID and keep it forever (Tools > Generate GUID in the Inno IDE).
AppId={{C9289B26-E3EA-46D7-B539-63901834398F}}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
UninstallDisplayName={#AppName}
UninstallDisplayIcon={app}\app.ico
DisableProgramGroupPage=yes
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
; The app writes to raw disks; the installer writes to Program Files -> admin.
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
OutputBaseFilename=StrixDiskCleaner-Setup-{#AppVersion}
OutputDir=dist

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional shortcuts:"

[Files]
Source: "..\StrixDiskCleaner.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\launch.vbs";          DestDir: "{app}"; Flags: ignoreversion
Source: "..\app.ico";             DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\README.md";        DestDir: "{app}"; Flags: ignoreversion
; --- Signed-launcher variant (optional) ------------------------------------
; If you build and SIGN ..\StrixDiskCleaner.exe (see build\ and sign.ps1),
; uncomment the next line to ship it, and switch the [Icons] targets below.
; Source: "..\StrixDiskCleaner.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
; --- Default: script-based launch (no opaque .exe, lowest FP risk) ----------
Name: "{group}\{#AppName}"; Filename: "{sys}\wscript.exe"; Parameters: """{app}\launch.vbs"""; \
    WorkingDir: "{app}"; IconFilename: "{app}\app.ico"; \
    Comment: "Professional secure data-destruction tool"
Name: "{autodesktop}\{#AppName}"; Filename: "{sys}\wscript.exe"; Parameters: """{app}\launch.vbs"""; \
    WorkingDir: "{app}"; IconFilename: "{app}\app.ico"; Tasks: desktopicon
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"

; --- Signed-launcher variant (use INSTEAD of the two Name: lines above) -----
; Name: "{group}\{#AppName}";          Filename: "{app}\StrixDiskCleaner.exe"; WorkingDir: "{app}"
; Name: "{autodesktop}\{#AppName}";    Filename: "{app}\StrixDiskCleaner.exe"; WorkingDir: "{app}"; Tasks: desktopicon

[UninstallDelete]
; Remove the per-user runtime copy the old .exe launcher extracted, if present.
Type: filesandordirs; Name: "{localappdata}\StrixDiskCleaner\app"

[Code]
// Optional: offer to remove saved settings on uninstall.
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  SettingsDir: String;
begin
  if CurUninstallStep = usPostUninstall then
  begin
    SettingsDir := ExpandConstant('{userappdata}\StrixDiskCleaner');
    if DirExists(SettingsDir) then
      if MsgBox('Also remove saved settings (theme, language, report folder)?',
                mbConfirmation, MB_YESNO) = IDYES then
        DelTree(SettingsDir, True, True, True);
  end;
end;
