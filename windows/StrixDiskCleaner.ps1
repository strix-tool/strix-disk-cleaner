# ============================================================================
#  Strix Disk Cleaner v2.3  -  Professional Secure Data Destruction Tool
#  v1.1: Hardware capability detection (NVMe SANICAP / ATA IDENTIFY / TCG-Opal),
#        per-disk recommendation panel, automatic TRIM, one-click restart to UEFI.
#  v1.2: 5-layer PROTECTION SHIELD - the system disk (C:) can never be targeted;
#        the worker re-validates number+serial+size+flags before every destructive step.
#  v1.2.1: BUGFIX - on raw disk access, the "dwDesiredAccess ... -1073741824" error was fixed
#          (PowerShell 5.1 hex constant overflowed Int32; the access value is now passed as UInt32).
#  v1.2.2: BUGFIX - the [Math]::Min call in the write loop was forced to the 64-bit (long) overload
#          ; on disks larger than ~2 GB the "val2 ... Int32" error was fixed.
#  v1.3: HEALTH and PERFORMANCE - Health/Life/Power-on-hours/Temperature columns in the disk list;
#        a detailed SMART block in the selection panel (wear, errors, failure prediction);
#        a read-only Speed Test button (sequential read + random 4K IOPS);
#        a pre-operation health summary added to the destruction report.
#  v2.0: DARK/LIGHT theme and a localized UI (settings stored persistently in %APPDATA%);
#        PDF destruction certificate (with a QR verification code), audible + visual notice on completion;
#        live temperature graph during wiping; Data-Trace Scan (entropy sampling);
#        Surface Test (bad-sector scan); Ctrl+select multiple disks for sequential queued wiping.
#  v2.1: DESKTOP EDITION - single language English; QR/network call removed (the app now
#        makes NO network connection at all; certificate verification is offline via code + SHA-256);
#        single-instance lock (mutex); XAML text escaping; strict type coercion in the settings file;
#        typed confirmation word ERASE; launcher EXE (embedded script + SHA-256 integrity).
#  v2.2: New name: STRIX DISK CLEANER. The taskbar/window now uses its own icon
#        (AppUserModelID + embedded icon; the PowerShell logo is hidden). The speed test now
#        also measures WRITE speed: HARMLESSLY via a temp file if a volume exists, otherwise with the user's
#        explicit consent, a raw write over the first 256 MB. Settings: %APPDATA%\StrixDiskCleaner.
#  v2.3: HPA/DCO hidden-area detection (ATA READ NATIVE MAX vs IDENTIFY); click-to-view SMART
#        raw attribute table; read-only content preview on disk selection (partitions/used space);
#        selectable report folder; automatic safe-eject of USB disks when done;
#        taskbar progress indicator; smart Data-Trace interpretation (partition structures only = clean).
#  Standards  : NIST SP 800-88 Rev.1 (Clear) and DoD 5220.22-M (3 passes)
#  Requires   : Windows 10/11, Administrator rights (requested automatically)
#  WARNING    : This tool IRREVERSIBLY destroys ALL data on the selected disk.
# ============================================================================

# ---- EARLIEST error trap (before anything else) ----------------------------
# The app runs console-less via the exe; a terminating error at startup would
# otherwise exit SILENTLY. This trap first writes to a file (not dependent on a MessageBox),
# then shows a window if possible.
$script:ErrorLog = Join-Path $env:TEMP 'StrixDiskCleaner_error.log'
trap {
    try {
        $message = ($_ | Out-String)
        $trace    = "$($_.ScriptStackTrace)"
        $full   = "[{0}] Strix Disk Cleaner startup error`r`n{1}`r`nStack:`r`n{2}" -f (Get-Date), $message, $trace
        [System.IO.File]::WriteAllText($script:ErrorLog, $full)
    } catch { }
    try {
        Add-Type -AssemblyName PresentationFramework -ErrorAction SilentlyContinue
        [System.Windows.MessageBox]::Show(
            ("Strix Disk Cleaner could not start.`r`n`r`n{0}`r`n`r`nSaved to:`r`n{1}" -f "$($_.Exception.Message)", $script:ErrorLog),
            'Strix Disk Cleaner - Startup Error', 'OK', 'Error') | Out-Null
    } catch { }
    exit 1
}

# ---- Relaunch elevated with Administrator rights ----------------------------
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal   = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    # Relaunch via ABSOLUTE path: instead of a bare "powershell.exe" we use the
    # full System32 path, so an attacker's fake powershell.exe planted on PATH
    # cannot be elevated via UAC (the installers use this absolute path too).
    $psExe = Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell\v1.0\powershell.exe'
    Start-Process -FilePath $psExe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$PSCommandPath`"" -Verb RunAs -WindowStyle Hidden
    exit
}

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase


# ============================================================================
# v2.0 INFRASTRUCTURE: Settings, Theme, Language
# ============================================================================

# ---- Taskbar identity: the window shows with its own icon/group ---------
if (-not ('GsTask' -as [type])) {
Add-Type -TypeDefinition @"
using System.Runtime.InteropServices;
public static class GsTask {
    [DllImport("shell32.dll", SetLastError=true)]
    public static extern int SetCurrentProcessExplicitAppUserModelID(
        [MarshalAs(UnmanagedType.LPWStr)] string AppID);
}
"@
}
try { [void][GsTask]::SetCurrentProcessExplicitAppUserModelID('Strix.DiskCleaner') } catch { }

# ============================================================================
# v2.4 INTERNATIONALIZATION: 13 languages (en + 12). The UI strings live inline
# in this script (below) so they always travel with the launcher/exe regardless of
# how it is packaged. The human-readable source of truth is i18n\<code>.json
# (English source string -> translation); the inline blocks are generated from those.
# The single-instance lock message is shown AFTER the language is resolved (moved
# further down), so even that message is localized.
# ============================================================================
# The 13 language codes (same set/order as the rest of the Strix suite website).
$script:LangCodes = @('en','de','fr','es','it','pt-BR','pl','uk','ru','sv','zh-CN','ja','ko')
# Native language names for the dropdown, stored as \uXXXX-escaped JSON so this
# file stays pure ASCII (PowerShell 5.1 reads ASCII reliably without a BOM);
# ConvertFrom-Json decodes them to real Unicode at runtime.
$script:LangNamesJson = @'
{"en":"English","de":"Deutsch","fr":"Français","es":"Español","it":"Italiano","pt-BR":"Português (BR)","pl":"Polski","uk":"Українська","ru":"Русский","sv":"Svenska","zh-CN":"简体中文","ja":"日本語","ko":"한국어"}
'@
$script:LangNames = @{}
try {
    $o = $script:LangNamesJson | ConvertFrom-Json
    foreach ($p in $o.PSObject.Properties) { $script:LangNames[$p.Name] = [string]$p.Value }
} catch { foreach ($c in $script:LangCodes) { $script:LangNames[$c] = $c } }

# ---- Map the OS UI culture to one of our 13 codes (mirrors strix_i18n.py) --------
function Get-OsLang([string]$default = 'en') {
    $raw = ''
    try { $raw = [System.Globalization.CultureInfo]::InstalledUICulture.Name } catch { $raw = '' }
    if ([string]::IsNullOrWhiteSpace($raw)) { try { $raw = [System.Globalization.CultureInfo]::CurrentUICulture.Name } catch { $raw = '' } }
    if ([string]::IsNullOrWhiteSpace($raw)) { return $default }
    $raw    = $raw.Replace('_','-')
    $parts  = $raw.Split('-')
    $prim   = $parts[0].ToLowerInvariant()
    $region = if ($parts.Count -gt 1) { $parts[1].ToUpperInvariant() } else { '' }
    $combo  = if ($region) { "$prim-$region" } else { $prim }
    foreach ($c in $script:LangCodes) { if ($c.ToLowerInvariant() -eq $combo.ToLowerInvariant()) { return $c } }  # exact (pt-BR, zh-CN)
    if ($prim -eq 'pt') { return 'pt-BR' }                                                                        # special-case: pt -> pt-BR
    if ($prim -eq 'zh') { return 'zh-CN' }                                                                        # special-case: zh -> zh-CN
    foreach ($c in $script:LangCodes) { if (($c.Split('-')[0]).ToLowerInvariant() -eq $prim) { return $c } }      # primary only (de-AT -> de)
    return $default
}

# ---- Persistent settings (%APPDATA%\StrixDiskCleaner\settings.json) -------------
$script:settingsPath = Join-Path $env:APPDATA 'StrixDiskCleaner\settings.json'
$script:Settings = @{ Theme='dark'; Language='en'; MethodIdx=0; Verify=$true; Format=$true; Report=$true; Pdf=$true; Sound=$true; ReportFolder=''; Eject=$true; Taskbar=$true }
$script:langExplicit = $false          # set true if a valid Language is found in the settings file
try {
    if (Test-Path $script:settingsPath) {
        $j = Get-Content $script:settingsPath -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($p in $j.PSObject.Properties) {
            if (-not $script:Settings.ContainsKey($p.Name)) { continue }
            try {
                switch ($p.Name) {
                    'Theme'        { $script:Settings.Theme = [string]$p.Value }
                    'Language'     { $lv = [string]$p.Value; if ($script:LangCodes -contains $lv) { $script:Settings.Language = $lv; $script:langExplicit = $true } }
                    'MethodIdx'   { $script:Settings.MethodIdx = [int]$p.Value }
                    'ReportFolder' { $script:Settings.ReportFolder = [string]$p.Value }
                    default       { $script:Settings[$p.Name] = [bool]$p.Value }
                }
            } catch { }
        }
    }
} catch { }
# First run (no valid language stored yet): auto-detect from the OS UI culture.
if (-not $script:langExplicit) { $script:Settings.Language = Get-OsLang }
function Save-Settings {
    try {
        $folder = Split-Path $script:settingsPath
        if (-not (Test-Path $folder)) { New-Item -ItemType Directory -Path $folder -Force | Out-Null }
        ($script:Settings | ConvertTo-Json) | Set-Content -Path $script:settingsPath -Encoding UTF8
    } catch { }
}

# ---- Theme palettes ---------------------------------------------------------
$script:Palettes = @{
  dark = @{ BG='#FF1B1D23'; PANEL='#FF232730'; PANEL2='#FF2E3440'; FG='#FFECEFF4'; FG2='#FFD8DEE9'
            SUB='#FF9AA5B1'; BORDER='#FF4C566A'; ACCENT='#FF88C0D0'; OK='#FFA3BE8C'
            WARNBG='#FF3B3222'; WARNFG='#FFEBCB8B'; RED='#FFBF3B46'; LOGBG='#FF15171C'; BAR='#FF5E81AC' }
  light = @{ BG='#FFF2F4F8'; PANEL='#FFFFFFFF'; PANEL2='#FFDDE3EC'; FG='#FF1B1D23'; FG2='#FF2E3440'
            SUB='#FF5B6472'; BORDER='#FFB8C0CC'; ACCENT='#FF1F6F8B'; OK='#FF3E7A3E'
            WARNBG='#FFFFF3D6'; WARNFG='#FF8A6D1D'; RED='#FFC0392B'; LOGBG='#FFE9ECF2'; BAR='#FF3C6EA5' }
}
$script:Theme = $script:Palettes[[string]$script:Settings.Theme]
if (-not $script:Theme) { $script:Theme = $script:Palettes.dark; $script:Settings.Theme = 'dark' }

# ---- UI strings ----------------------------------------------------------
$script:Languages = @{
en = @{
  window_title='Strix Disk Cleaner v2.3 - Professional Data Destruction Tool'
  sub_title='NIST SP 800-88 and DoD 5220.22-M compliant, irreversible disk wiping'
  lbl_theme='Theme:'; theme_dark='Dark'; theme_light='Light'
  col_disk='Disk'; col_model='Model'; col_type='Type'; col_bus='Bus'; col_size='Size'
  col_serial='Serial No'; col_health='Health'; col_life='Life'; col_hours='Hours'; col_temp='Temp'
  btn_uefi='Restart into UEFI/BIOS Settings'
  lbl_method='Wipe Method:'
  y0='NIST SP 800-88 Clear  -  Single pass 0x00 (RECOMMENDED, sufficient for modern drives)'
  y1='Single pass cryptographic random data'
  y2='DoD 5220.22-M  -  3 passes (0x00 / 0xFF / random) + verification'
  y3='Advanced  -  7 passes (VSITR-like, very slow)'
  chk_verify='Verify after wiping (read back from disk and check)'
  chk_format='Make the disk usable when done (create partition + quick format)'
  chk_report='Save a Data Destruction Report (certificate) to the report folder'
  chk_pdf='Also create a PDF certificate (with verification code; works with the report option)'
  chk_sound='Play a sound and flash the window when finished'
  btn_refresh='Refresh List'; btn_speed='Speed Test'; btn_trace='Data Trace Scan'
  btn_surface='Surface Test'; btn_wipe='SECURE ERASE'; btn_cancel='Cancel'
  status_ready='Ready. Select the disk(s) to wipe (hold Ctrl to select multiple).'
  confirm_title='Confirm by Typing'
  confirm_text='For safety, type ERASE in capital letters in the box below to continue:'
  btn_back='Back'; btn_startwipe='START WIPING'
  ready_log='Strix Disk Cleaner v2.3 ready. Hardware capabilities and health (SMART) data are queried automatically when you select a disk.'
  protect_log='PROTECTION SHIELD ACTIVE: the disk holding {0} and all boot/system disks can never be targeted; identity checks are repeated during wiping.'
  first_disk_select='Please select a disk from the list first.'
  protect_block_log='PROTECTION SHIELD BLOCKED: {0}'
  protect_block_msg="PROTECTION SHIELD engaged:`n`n{0}`n`nThis disk can never be wiped."
  protect_block_title='Strix Disk Cleaner - System Disk Protection'
  summary_start='ALL DATA ON THE FOLLOWING {0} DISK(S) WILL BE PERMANENTLY DESTROYED:'
  summary_disk='  Disk {0}: {1}  |  {2}  |  {3} ({4})  |  Serial: {5}'
  summary_method='Method: {0}'
  summary_final='This CANNOT be undone. Continue?'
  final_warning_title='FINAL WARNING'
  confirm_none_log='Operation cancelled by the user (confirmation not given).'
  cancel_question="Are you sure you want to cancel?`nThe disk will be left partially wiped (inconsistent)."
  cancel_title='Cancel Confirmation'
  cancel_question_read="Are you sure you want to cancel the surface/scan operation?`nData was not touched; the operation will simply be interrupted."
  t_speed='Speed: {0}/s'
  t_remaining='Est. remaining: {0}'
  wipe_started_log='Secure wipe started for disk {0}. Method: {1}'
  queue_log='{0} disks queued; they will be wiped one after another.'
  queue_next_log='Moving to the next disk in the queue: Disk {0}...'
  queue_cancel_log='Remaining queued disks were skipped due to error/cancellation.'
  done_msg="Done!`n`nAll data on {0} disk(s) was irreversibly destroyed according to the selected standard."
  report_msg="`n`nReport(s) saved to the report folder."
  success_title='Strix Disk Cleaner - Success'
  speed_started_log='Speed test started: Disk {0} ({1}) - read phase is always safe; write phase uses a temporary file when possible.'
  speed_phase1='Speed test: sequential read... {0}'
  speed_phase2='Speed test: random 4K read...'
  speed_read_summary='Read : sequential {0}/s  |  random 4K {1:N0} IOPS (avg {2:N1} ms)'
  speed_write_summary='Write: sequential {0}/s  |  random 4K {1:N0} IOPS (avg {2:N1} ms)'
  speed_write_raw_summary='Write: sequential {0}/s  (raw mode; random-write phase skipped)'
  speed_phase3='Speed test: sequential write... {0}'
  speed_phase4='Speed test: random 4K write...'
  speed_write_file_log='Write test target: temporary file on {0}: (non-destructive, deleted afterwards).'
  speed_write_raw_question="This disk has no mounted volume with enough free space for a SAFE write test.`nWrite speed can only be measured by OVERWRITING the first {0} of the disk with test data - whatever is stored in that area will be DESTROYED.`n`nProceed with the destructive raw write test?"
  speed_write_none='Write test skipped.'
  speed_done_log='Speed test finished. {0}'
  speed_note='Note: file-based write results include filesystem overhead, so they can read slightly below raw device speed.'
  speed_status='Speed test finished. Results are in the log.'
  speed_msg="Disk {0} ({1})`n`n{2}"
  speed_title='Strix Disk Cleaner - Speed Test'
  speed_error_log='Speed test ERROR: {0}'
  trace_started_log='Data trace scan started: Disk {0} - read-only sampling.'
  trace_status='Scanning for data traces (reading random samples)...'
  trace_summary='Samples: {0} blocks  |  Containing data traces: {1} ({2}%)  |  Zeroed (blank): {3}  |  0xFF: {4}  |  Avg entropy: {5:N2} bits/byte'
  trace_note_empty='The disk appears largely blank/zeroed.'
  trace_note_present='RECOVERABLE DATA TRACES are present - secure wiping is recommended before disposal.'
  trace_note_encrypted='High entropy: the data may be encrypted/compressed; secure wiping is still recommended.'
  trace_title='Strix Disk Cleaner - Data Trace Scan'
  trace_error_log='Data trace scan ERROR: {0}'
  surface_question="The surface test reads the ENTIRE disk; for {0} this may take a long time depending on disk speed.`nData is not touched. Start?"
  surface_title='Surface Test'
  surface_started_log='Surface test started: Disk {0} ({1}) - the whole surface will be scanned read-only.'
  surface_ok_msg="Surface test finished.`n`nNo unreadable blocks were found - the surface looks healthy."
  surface_bad_msg="Surface test finished.`n`nWARNING: {0} unreadable 64 KB blocks were found!`nFirst locations (byte offsets):`n{1}`n`nThis disk is not suitable for reliable storage."
  pdf_ok_log='PDF certificate created: {0}'
  pdf_html_log='PDF converter (Edge) not found; HTML certificate saved: {0} (open it in a browser and print to PDF with Ctrl+P).'
  pdf_error_log='PDF certificate could not be created: {0}'
  theme_dil_question='The application will restart to apply this change. Continue?'
  theme_dil_title='Restart Required'
  busy_msg='This setting cannot be changed while an operation is running.'
  temp_fmt='Temperature: {0} C (peak: {1} C)'
  temp_report='Temp During Wipe  : peak {0} C measured'
  uefi_question="The computer will restart directly into UEFI/BIOS settings in 5 seconds.`nHave you saved your open files? (Works on UEFI systems only.)"
  uefi_title='Restart into UEFI/BIOS'
  health_panel='HEALTH / SMART:'
  m_op_started='Operation started: Disk {0} ({1}), {2} GB'
  m_method='Method: {0}'
  m_protect_ok='Protection shield: target disk identity verified - NOT the system disk, does not contain {0}.'
  m_status_partition='Clearing partition table...'
  m_cleardisk_note='Note: Clear-Disk warning ({0}) - continuing.'
  m_raw_error='Raw disk access could not be opened (Win32 error: {0}). Close programs using the disk and try again.'
  m_status_write='Writing to disk...'
  m_pass_fmt='Pass {0} / {1}  ({2})'
  m_pass_start='Pass {0}/{1} started (pattern: {2}).'
  m_pass_done='Pass {0}/{1} completed.'
  m_random='random'
  m_status_verify='Verifying (reading back from disk)...'
  m_verification_label='Verification'
  m_dv_fail='VERIFICATION FAILED: expected pattern not found in {0} sampled blocks!'
  m_dv_ok_pattern='PASSED ({0} sample points verified against the pattern)'
  m_dv_ok_rand='PASSED ({0} sample points read back; last pass was random so no pattern comparison applies)'
  m_dv_log='Verification: {0}'
  m_notdone='Not performed'
  m_status_format='Preparing the disk again (partition + format)...'
  m_format_log='Creating a new partition and quick-formatting...'
  m_disk_ready='Disk ready: formatted as drive {0}: ({1}).'
  m_status_trim='Sending TRIM (notifying the controller about free blocks)...'
  m_trim_start='SSD detected: running Optimize-Volume -ReTrim...'
  m_trim_ok='TRIM finished: the controller was told to release stale blocks in its mapping table as well.'
  m_trim_error='TRIM step skipped: {0}'
  m_trim_none_partition='Note: TRIM needs a volume; ReTrim was not applied because the prepare-disk option is off.'
  m_format_skipped='Formatting skipped: {0} (You can initialize the disk manually in Disk Management.)'
  m_report_saved='Destruction report saved: {0}'
  m_status_done='COMPLETED - Data has been irreversibly destroyed.'
  m_op_ok='Operation completed successfully.'
  m_cancel='Operation cancelled by the user. WARNING: the disk may be partially wiped; data is inconsistent.'
  m_cancel_read='Scan cancelled by the user (data was not touched).'
  m_error='ERROR: {0}'
  m_k_boot='PROTECTION ({0}): Target disk currently appears to be the BOOT disk - operation stopped!'
  m_k_system='PROTECTION ({0}): Target disk carries the SYSTEM/EFI partition - operation stopped!'
  m_k_serial_match='PROTECTION ({0}): Target disk serial matches the protected system disk - operation stopped!'
  m_k_num='PROTECTION ({0}): Target disk number is on the protected list - operation stopped!'
  m_k_serial_changed='PROTECTION ({0}): Disk identity CHANGED! Confirmed serial {1}, found {2}. Devices may have been renumbered - stopped for safety.'
  m_k_size='PROTECTION ({0}): Disk size does not match the confirmed one (expected {1}, found {2}) - operation stopped.'
  m_k_c='PROTECTION ({0}): Target disk hosts the {1} drive - operation stopped!'
  m_y_status='Scanning surface (read-only)...'
  m_y_error='Unreadable region: starting at offset {0}, {1} failed 64 KB sub-blocks.'
  m_y_ok='Surface test finished: no unreadable blocks found.'
  m_y_done='Surface test finished: {0} unreadable 64 KB blocks.'
  m_trim_applied='Applied - free blocks reported to the controller'
  m_trim_notapplied='Not applied'
  r_template="=====================================================================`n                DATA DESTRUCTION REPORT / CERTIFICATE`n=====================================================================`nCreated By        : Strix Disk Cleaner v2.3`nReport Date       : {0}`nComputer          : {1}  (User: {2})`n`n--- DESTROYED MEDIA ---`nDisk Number       : {3}`nModel             : {4}`nSerial Number     : {5}`nCapacity          : {6} GB ({7} bytes)`nMedia Type        : {8}  |  Bus: {9}`nDetected          : {10}`nPre-Wipe Health   : {11}`n`n--- METHOD APPLIED ---`nStandard / Method : {12}`nPass Count        : {13}`nTotal Written     : {14} GB`nVerification      : {15}`nTRIM (ReTrim)     : {16}`nDuration          : {17} min {18} s`nResult            : SUCCESS - every sector of the media was overwritten.`n`nNOTE (NIST SP 800-88 Rev.1): Overwriting provides the Clear level.`nFor the Purge level on SSD/NVMe media, additional step:`n{19}`n====================================================================="
  s_healthy='Healthy'; s_warning='WARNING'; s_unhealthy='UNHEALTHY'
  s_status='Status: {0}'
  s_wear='Wear: {0}% (estimated remaining life ~{1}%)'
  s_wear_none='Wear data not reported'
  s_hours='Power-on: {0:N0} hours (~{1:N0} days)'
  s_temp='Temperature: {0} C'
  s_temp_max=' (highest seen: {0} C)'
  s_errors='Errors: read {0} (uncorrectable: {1}), write {2} (uncorrectable: {3})'
  s_smart='SMART failure prediction: {0}'
  s_smart_bad='FAILURE PREDICTED - BACK UP NOW!'
  s_smart_good='Normal (no failure predicted)'
  s_counter_none='Reliability counters are not exposed for this disk/bus.'
  s_query_none='Health query failed (USB enclosures/bridges usually do not pass SMART data through).'
  cert_title='DATA DESTRUCTION CERTIFICATE'
  cert_sub='Secure data destruction compliant with NIST SP 800-88 Rev.1'
  cert_verification='Verification Code (report SHA-256)'
  cert_field_disk='Disk'; cert_field_serial='Serial No'; cert_field_capacity='Capacity'; cert_field_method='Method'
  cert_field_pass='Passes'; cert_field_dv='Verification'; cert_field_duration='Duration'; cert_field_date='Date'
  cert_field_pc='Computer'; cert_field_health='Pre-Wipe Health'; cert_field_result='Result'; cert_field_temp='Peak Temperature'
  cert_result='SUCCESS - all sectors overwritten'
  # --- v2.3 new strings ---
  lbl_report_folder='Report folder:'; btn_report_folder='Change...'; report_folder_title='Choose where reports/certificates are saved'
  chk_eject='Safely eject USB disks when finished'
  chk_task='Show wipe progress on the taskbar icon'
  hpa_none='No hidden area (HPA/DCO): the full physical capacity is addressable.'
  hpa_present='HIDDEN AREA DETECTED (HPA/DCO): {0} of this disk ({1} sectors) is hidden from the OS and will NOT be overwritten. For full destruction use the manufacturer tool or a hardware Secure Erase (see README).'
  hpa_query_none='Hidden-area (HPA/DCO) check not available on this bus (USB bridges usually block ATA commands).'
  preview_title='Disk contents (read-only preview)'
  preview_empty='No mounted volumes / partitions detected on this disk.'
  preview_partition='  {0}: {1}  |  {2} of {3} used ({4}% full)  |  {5}'
  preview_partition_noletter='  Partition {0}: {1}  (no drive letter)'
  preview_summary='This disk has {0} partition(s), about {1} of data in total.'
  preview_title_panel='CONTENTS:'
  smart_title='SMART Attributes - Disk {0}'
  smart_col_id='ID'; smart_col_name='Attribute'; smart_col_value='Value'; smart_col_worst='Worst'; smart_col_raw='Raw'; smart_col_status='Status'
  smart_none='Raw SMART attribute table is not available for this disk (USB bridge or NVMe - the health summary above still applies).'
  smart_btn='SMART Details'
  smart_ok='OK'; smart_check='CHECK'
  eject_ok='USB disk {0} ejected - you can safely unplug it now.'
  eject_error='Automatic eject failed ({0}); use the tray "Safely Remove Hardware" icon.'
  trace_note_clean='The disk is essentially blank - only partition structures were found (no recoverable user data).'
  # --- v2.4 i18n new strings ---
  lbl_language='Language:'
  already_running='Strix Disk Cleaner is already running.'
}
}

# ============================================================================
# v2.4: inline translations for the other 12 languages. Non-ASCII is stored as
# \uXXXX escapes (so this .ps1 stays pure ASCII and PowerShell 5.1 reads it
# without a BOM); ConvertFrom-Json decodes them at runtime. Each language table
# starts as a full clone of English and overlays its translations, so every key
# is ALWAYS present (missing/blank translations transparently fall back to
# English - this guarantees the safety/protection messages are never empty).
# GENERATED from i18n\<code>.json by windows\build\Build-I18n.ps1 - do not hand-edit.
# <I18N-DATA-START>
$script:I18nData = @'
{
"de":{"window_title":"Strix Disk Cleaner v2.3 - Professionelles Werkzeug zur Datenvernichtung","sub_title":"NIST SP 800-88- und DoD 5220.22-M-konformes, unwiderrufliches Löschen von Datenträgern","lbl_theme":"Design:","theme_dark":"Dunkel","theme_light":"Hell","col_disk":"Datenträger","col_model":"Modell","col_type":"Typ","col_size":"Größe","col_serial":"Seriennr.","col_health":"Zustand","col_life":"Lebensdauer","col_hours":"Stunden","col_temp":"Temp.","btn_uefi":"In UEFI/BIOS-Einstellungen neu starten","lbl_method":"Löschmethode:","y0":"NIST SP 800-88 Clear  -  Einzeldurchlauf 0x00 (EMPFOHLEN, ausreichend für moderne Laufwerke)","y1":"Einzeldurchlauf mit kryptografischen Zufallsdaten","y2":"DoD 5220.22-M  -  3 Durchläufe (0x00 / 0xFF / Zufall) + Überprüfung","y3":"Erweitert  -  7 Durchläufe (VSITR-ähnlich, sehr langsam)","chk_verify":"Nach dem Löschen überprüfen (vom Datenträger zurücklesen und prüfen)","chk_format":"Datenträger nach Abschluss nutzbar machen (Partition erstellen + Schnellformatierung)","chk_report":"Einen Datenvernichtungsbericht (Zertifikat) im Berichtsordner speichern","chk_pdf":"Zusätzlich ein PDF-Zertifikat erstellen (mit Prüfcode; funktioniert mit der Berichtsoption)","chk_sound":"Nach Abschluss einen Ton abspielen und das Fenster blinken lassen","btn_refresh":"Liste aktualisieren","btn_speed":"Geschwindigkeitstest","btn_trace":"Datenspuren-Scan","btn_surface":"Oberflächentest","btn_wipe":"SICHER LÖSCHEN","btn_cancel":"Abbrechen","status_ready":"Bereit. Wählen Sie den/die zu löschenden Datenträger aus (Ctrl gedrückt halten für Mehrfachauswahl).","confirm_title":"Durch Eingabe bestätigen","confirm_text":"Geben Sie zur Sicherheit ERASE in Großbuchstaben in das Feld unten ein, um fortzufahren:","btn_back":"Zurück","btn_startwipe":"LÖSCHEN STARTEN","ready_log":"Strix Disk Cleaner v2.3 bereit. Hardwarefähigkeiten und Zustandsdaten (SMART) werden bei der Auswahl eines Datenträgers automatisch abgefragt.","protect_log":"SCHUTZSCHILD AKTIV: Der Datenträger mit {0} sowie alle Boot-/Systemdatenträger können niemals ausgewählt werden; Identitätsprüfungen werden während des Löschens wiederholt.","first_disk_select":"Bitte wählen Sie zuerst einen Datenträger aus der Liste aus.","protect_block_log":"SCHUTZSCHILD BLOCKIERT: {0}","protect_block_msg":"SCHUTZSCHILD ausgelöst:\n\n{0}\n\nDieser Datenträger kann niemals gelöscht werden.","protect_block_title":"Strix Disk Cleaner - Systemdatenträgerschutz","summary_start":"ALLE DATEN AUF DEN FOLGENDEN {0} DATENTRÄGER(N) WERDEN DAUERHAFT VERNICHTET:","summary_disk":"  Datenträger {0}: {1}  |  {2}  |  {3} ({4})  |  Seriennr.: {5}","summary_method":"Methode: {0}","summary_final":"Dies kann NICHT rückgängig gemacht werden. Fortfahren?","final_warning_title":"LETZTE WARNUNG","confirm_none_log":"Vorgang vom Benutzer abgebrochen (keine Bestätigung erteilt).","cancel_question":"Möchten Sie den Vorgang wirklich abbrechen?\nDer Datenträger bleibt teilweise gelöscht (inkonsistent) zurück.","cancel_title":"Abbruchbestätigung","cancel_question_read":"Möchten Sie den Oberflächen-/Scanvorgang wirklich abbrechen?\nDie Daten wurden nicht verändert; der Vorgang wird lediglich unterbrochen.","t_speed":"Geschwindigkeit: {0}/s","t_remaining":"Geschätzte Restzeit: {0}","wipe_started_log":"Sicheres Löschen für Datenträger {0} gestartet. Methode: {1}","queue_log":"{0} Datenträger in der Warteschlange; sie werden nacheinander gelöscht.","queue_next_log":"Wechsel zum nächsten Datenträger in der Warteschlange: Datenträger {0}...","queue_cancel_log":"Verbleibende Datenträger in der Warteschlange wurden aufgrund eines Fehlers/Abbruchs übersprungen.","done_msg":"Fertig!\n\nAlle Daten auf {0} Datenträger(n) wurden gemäß dem gewählten Standard unwiderruflich vernichtet.","report_msg":"\n\nBericht(e) im Berichtsordner gespeichert.","success_title":"Strix Disk Cleaner - Erfolg","speed_started_log":"Geschwindigkeitstest gestartet: Datenträger {0} ({1}) - die Lesephase ist immer sicher; die Schreibphase verwendet nach Möglichkeit eine temporäre Datei.","speed_phase1":"Geschwindigkeitstest: sequenzielles Lesen... {0}","speed_phase2":"Geschwindigkeitstest: zufälliges 4K-Lesen...","speed_read_summary":"Lesen : sequenziell {0}/s  |  zufällig 4K {1:N0} IOPS (Ø {2:N1} ms)","speed_write_summary":"Schreiben: sequenziell {0}/s  |  zufällig 4K {1:N0} IOPS (Ø {2:N1} ms)","speed_write_raw_summary":"Schreiben: sequenziell {0}/s  (Rohmodus; Zufallsschreibphase übersprungen)","speed_phase3":"Geschwindigkeitstest: sequenzielles Schreiben... {0}","speed_phase4":"Geschwindigkeitstest: zufälliges 4K-Schreiben...","speed_write_file_log":"Schreibtestziel: temporäre Datei auf {0}: (nicht zerstörend, wird anschließend gelöscht).","speed_write_raw_question":"Dieser Datenträger hat kein eingebundenes Volume mit genügend freiem Speicher für einen SICHEREN Schreibtest.\nDie Schreibgeschwindigkeit kann nur gemessen werden, indem die ersten {0} des Datenträgers mit Testdaten ÜBERSCHRIEBEN werden - alles, was in diesem Bereich gespeichert ist, wird VERNICHTET.\n\nMit dem zerstörenden Roh-Schreibtest fortfahren?","speed_write_none":"Schreibtest übersprungen.","speed_done_log":"Geschwindigkeitstest abgeschlossen. {0}","speed_note":"Hinweis: Dateibasierte Schreibergebnisse enthalten Dateisystem-Overhead und können daher etwas unter der reinen Gerätegeschwindigkeit liegen.","speed_status":"Geschwindigkeitstest abgeschlossen. Die Ergebnisse befinden sich im Protokoll.","speed_msg":"Datenträger {0} ({1})\n\n{2}","speed_title":"Strix Disk Cleaner - Geschwindigkeitstest","speed_error_log":"FEHLER beim Geschwindigkeitstest: {0}","trace_started_log":"Datenspuren-Scan gestartet: Datenträger {0} - schreibgeschützte Stichprobenentnahme.","trace_status":"Suche nach Datenspuren (Lesen von Zufallsstichproben)...","trace_summary":"Stichproben: {0} Blöcke  |  Mit Datenspuren: {1} ({2}%)  |  Genullt (leer): {3}  |  0xFF: {4}  |  Ø Entropie: {5:N2} Bit/Byte","trace_note_empty":"Der Datenträger scheint weitgehend leer/genullt zu sein.","trace_note_present":"WIEDERHERSTELLBARE DATENSPUREN sind vorhanden - vor der Entsorgung wird sicheres Löschen empfohlen.","trace_note_encrypted":"Hohe Entropie: Die Daten sind möglicherweise verschlüsselt/komprimiert; sicheres Löschen wird dennoch empfohlen.","trace_title":"Strix Disk Cleaner - Datenspuren-Scan","trace_error_log":"FEHLER beim Datenspuren-Scan: {0}","surface_question":"Der Oberflächentest liest den GESAMTEN Datenträger; bei {0} kann dies je nach Datenträgergeschwindigkeit lange dauern.\nDie Daten werden nicht verändert. Starten?","surface_title":"Oberflächentest","surface_started_log":"Oberflächentest gestartet: Datenträger {0} ({1}) - die gesamte Oberfläche wird schreibgeschützt gescannt.","surface_ok_msg":"Oberflächentest abgeschlossen.\n\nEs wurden keine unlesbaren Blöcke gefunden - die Oberfläche wirkt einwandfrei.","surface_bad_msg":"Oberflächentest abgeschlossen.\n\nWARNUNG: {0} unlesbare 64-KB-Blöcke wurden gefunden!\nErste Positionen (Byte-Offsets):\n{1}\n\nDieser Datenträger ist nicht für zuverlässige Speicherung geeignet.","pdf_ok_log":"PDF-Zertifikat erstellt: {0}","pdf_html_log":"PDF-Konverter (Edge) nicht gefunden; HTML-Zertifikat gespeichert: {0} (in einem Browser öffnen und mit Ctrl+P als PDF drucken).","pdf_error_log":"PDF-Zertifikat konnte nicht erstellt werden: {0}","theme_dil_question":"Die Anwendung wird neu gestartet, um diese Änderung zu übernehmen. Fortfahren?","theme_dil_title":"Neustart erforderlich","busy_msg":"Diese Einstellung kann während eines laufenden Vorgangs nicht geändert werden.","temp_fmt":"Temperatur: {0} C (Spitze: {1} C)","temp_report":"Temp. während Löschen  : Spitze {0} C gemessen","uefi_question":"Der Computer startet in 5 Sekunden direkt in die UEFI/BIOS-Einstellungen neu.\nHaben Sie Ihre geöffneten Dateien gespeichert? (Funktioniert nur auf UEFI-Systemen.)","uefi_title":"In UEFI/BIOS neu starten","health_panel":"ZUSTAND / SMART:","m_op_started":"Vorgang gestartet: Datenträger {0} ({1}), {2} GB","m_method":"Methode: {0}","m_protect_ok":"Schutzschild: Identität des Zieldatenträgers verifiziert - NICHT der Systemdatenträger, enthält nicht {0}.","m_status_partition":"Partitionstabelle wird gelöscht...","m_cleardisk_note":"Hinweis: Clear-Disk-Warnung ({0}) - wird fortgesetzt.","m_raw_error":"Roh-Datenträgerzugriff konnte nicht geöffnet werden (Win32-Fehler: {0}). Schließen Sie Programme, die den Datenträger verwenden, und versuchen Sie es erneut.","m_status_write":"Wird auf Datenträger geschrieben...","m_pass_fmt":"Durchlauf {0} / {1}  ({2})","m_pass_start":"Durchlauf {0}/{1} gestartet (Muster: {2}).","m_pass_done":"Durchlauf {0}/{1} abgeschlossen.","m_random":"Zufall","m_status_verify":"Überprüfung läuft (Zurücklesen vom Datenträger)...","m_verification_label":"Überprüfung","m_dv_fail":"ÜBERPRÜFUNG FEHLGESCHLAGEN: erwartetes Muster in {0} entnommenen Blöcken nicht gefunden!","m_dv_ok_pattern":"BESTANDEN ({0} Stichprobenpunkte gegen das Muster verifiziert)","m_dv_ok_rand":"BESTANDEN ({0} Stichprobenpunkte zurückgelesen; der letzte Durchlauf war zufällig, daher entfällt der Mustervergleich)","m_dv_log":"Überprüfung: {0}","m_notdone":"Nicht durchgeführt","m_status_format":"Datenträger wird erneut vorbereitet (Partition + Formatierung)...","m_format_log":"Neue Partition wird erstellt und schnellformatiert...","m_disk_ready":"Datenträger bereit: als Laufwerk {0}: formatiert ({1}).","m_status_trim":"TRIM wird gesendet (Controller über freie Blöcke informieren)...","m_trim_start":"SSD erkannt: Optimize-Volume -ReTrim wird ausgeführt...","m_trim_ok":"TRIM abgeschlossen: Der Controller wurde angewiesen, auch veraltete Blöcke in seiner Zuordnungstabelle freizugeben.","m_trim_error":"TRIM-Schritt übersprungen: {0}","m_trim_none_partition":"Hinweis: TRIM benötigt ein Volume; ReTrim wurde nicht angewendet, da die Option zur Datenträgervorbereitung deaktiviert ist.","m_format_skipped":"Formatierung übersprungen: {0} (Sie können den Datenträger in der Datenträgerverwaltung manuell initialisieren.)","m_report_saved":"Vernichtungsbericht gespeichert: {0}","m_status_done":"ABGESCHLOSSEN - Die Daten wurden unwiderruflich vernichtet.","m_op_ok":"Vorgang erfolgreich abgeschlossen.","m_cancel":"Vorgang vom Benutzer abgebrochen. WARNUNG: Der Datenträger ist möglicherweise teilweise gelöscht; die Daten sind inkonsistent.","m_cancel_read":"Scan vom Benutzer abgebrochen (die Daten wurden nicht verändert).","m_error":"FEHLER: {0}","m_k_boot":"SCHUTZ ({0}): Der Zieldatenträger scheint derzeit der BOOT-Datenträger zu sein - Vorgang gestoppt!","m_k_system":"SCHUTZ ({0}): Der Zieldatenträger enthält die SYSTEM/EFI-Partition - Vorgang gestoppt!","m_k_serial_match":"SCHUTZ ({0}): Die Seriennummer des Zieldatenträgers stimmt mit dem geschützten Systemdatenträger überein - Vorgang gestoppt!","m_k_num":"SCHUTZ ({0}): Die Nummer des Zieldatenträgers steht auf der Schutzliste - Vorgang gestoppt!","m_k_serial_changed":"SCHUTZ ({0}): Datenträgeridentität HAT SICH GEÄNDERT! Bestätigte Seriennummer {1}, gefunden {2}. Geräte wurden möglicherweise neu nummeriert - zur Sicherheit gestoppt.","m_k_size":"SCHUTZ ({0}): Die Datenträgergröße stimmt nicht mit der bestätigten überein (erwartet {1}, gefunden {2}) - Vorgang gestoppt.","m_k_c":"SCHUTZ ({0}): Der Zieldatenträger beherbergt das Laufwerk {1} - Vorgang gestoppt!","m_y_status":"Oberfläche wird gescannt (schreibgeschützt)...","m_y_error":"Unlesbarer Bereich: beginnend bei Offset {0}, {1} fehlgeschlagene 64-KB-Unterblöcke.","m_y_ok":"Oberflächentest abgeschlossen: keine unlesbaren Blöcke gefunden.","m_y_done":"Oberflächentest abgeschlossen: {0} unlesbare 64-KB-Blöcke.","m_trim_applied":"Angewendet - freie Blöcke an den Controller gemeldet","m_trim_notapplied":"Nicht angewendet","r_template":"=====================================================================\n                DATENVERNICHTUNGSBERICHT / ZERTIFIKAT\n=====================================================================\nErstellt von      : Strix Disk Cleaner v2.3\nBerichtsdatum     : {0}\nComputer          : {1}  (Benutzer: {2})\n\n--- VERNICHTETES MEDIUM ---\nDatenträgernummer : {3}\nModell            : {4}\nSeriennummer      : {5}\nKapazität         : {6} GB ({7} Bytes)\nMedientyp         : {8}  |  Bus: {9}\nErkannt           : {10}\nZustand vor Löschung : {11}\n\n--- ANGEWENDETE METHODE ---\nStandard / Methode : {12}\nDurchlaufanzahl   : {13}\nInsgesamt geschrieben : {14} GB\nÜberprüfung       : {15}\nTRIM (ReTrim)     : {16}\nDauer             : {17} Min {18} s\nErgebnis          : ERFOLG - jeder Sektor des Mediums wurde überschrieben.\n\nHINWEIS (NIST SP 800-88 Rev.1): Das Überschreiben erreicht die Stufe Clear.\nFür die Stufe Purge bei SSD/NVMe-Medien, zusätzlicher Schritt:\n{19}\n=====================================================================","s_healthy":"Einwandfrei","s_warning":"WARNUNG","s_unhealthy":"BEEINTRÄCHTIGT","s_wear":"Verschleiß: {0}% (geschätzte Restlebensdauer ~{1}%)","s_wear_none":"Keine Verschleißdaten gemeldet","s_hours":"Betriebsdauer: {0:N0} Stunden (~{1:N0} Tage)","s_temp":"Temperatur: {0} C","s_temp_max":" (höchster Wert: {0} C)","s_errors":"Fehler: Lesen {0} (nicht korrigierbar: {1}), Schreiben {2} (nicht korrigierbar: {3})","s_smart":"SMART-Ausfallvorhersage: {0}","s_smart_bad":"AUSFALL VORHERGESAGT - JETZT SICHERN!","s_smart_good":"Normal (kein Ausfall vorhergesagt)","s_counter_none":"Zuverlässigkeitszähler werden für diesen Datenträger/Bus nicht bereitgestellt.","s_query_none":"Zustandsabfrage fehlgeschlagen (USB-Gehäuse/-Bridges leiten SMART-Daten üblicherweise nicht durch).","cert_title":"DATENVERNICHTUNGSZERTIFIKAT","cert_sub":"Sichere Datenvernichtung gemäß NIST SP 800-88 Rev.1","cert_verification":"Prüfcode (Bericht SHA-256)","cert_field_disk":"Datenträger","cert_field_serial":"Seriennr.","cert_field_capacity":"Kapazität","cert_field_method":"Methode","cert_field_pass":"Durchläufe","cert_field_dv":"Überprüfung","cert_field_duration":"Dauer","cert_field_date":"Datum","cert_field_health":"Zustand vor Löschung","cert_field_result":"Ergebnis","cert_field_temp":"Spitzentemperatur","cert_result":"ERFOLG - alle Sektoren überschrieben","lbl_report_folder":"Berichtsordner:","btn_report_folder":"Ändern...","report_folder_title":"Wählen Sie, wo Berichte/Zertifikate gespeichert werden","chk_eject":"USB-Datenträger nach Abschluss sicher auswerfen","chk_task":"Löschfortschritt am Taskleistensymbol anzeigen","hpa_none":"Kein versteckter Bereich (HPA/DCO): Die gesamte physische Kapazität ist adressierbar.","hpa_present":"VERSTECKTER BEREICH ERKANNT (HPA/DCO): {0} dieses Datenträgers ({1} Sektoren) sind vor dem Betriebssystem verborgen und werden NICHT überschrieben. Für eine vollständige Vernichtung verwenden Sie das Herstellerwerkzeug oder ein Hardware-Secure-Erase (siehe README).","hpa_query_none":"Prüfung auf versteckte Bereiche (HPA/DCO) auf diesem Bus nicht verfügbar (USB-Bridges blockieren üblicherweise ATA-Befehle).","preview_title":"Datenträgerinhalt (schreibgeschützte Vorschau)","preview_empty":"Keine eingebundenen Volumes / Partitionen auf diesem Datenträger erkannt.","preview_partition":"  {0}: {1}  |  {2} von {3} belegt ({4}% voll)  |  {5}","preview_partition_noletter":"  Partition {0}: {1}  (kein Laufwerksbuchstabe)","preview_summary":"Dieser Datenträger hat {0} Partition(en), insgesamt etwa {1} an Daten.","preview_title_panel":"INHALT:","smart_title":"SMART-Attribute - Datenträger {0}","smart_col_name":"Attribut","smart_col_value":"Wert","smart_col_worst":"Schlechtester","smart_col_raw":"Rohwert","smart_none":"Die SMART-Rohattributtabelle ist für diesen Datenträger nicht verfügbar (USB-Bridge oder NVMe - die obige Zustandszusammenfassung gilt weiterhin).","smart_btn":"SMART-Details","smart_check":"PRÜFEN","eject_ok":"USB-Datenträger {0} ausgeworfen - Sie können ihn jetzt sicher abziehen.","eject_error":"Automatisches Auswerfen fehlgeschlagen ({0}); verwenden Sie das Infobereich-Symbol \"Hardware sicher entfernen\".","trace_note_clean":"Der Datenträger ist im Wesentlichen leer - es wurden nur Partitionsstrukturen gefunden (keine wiederherstellbaren Benutzerdaten).","lbl_language":"Sprache:","already_running":"Strix Disk Cleaner wird bereits ausgeführt."},
"fr":{"window_title":"Strix Disk Cleaner v2.3 - Outil professionnel de destruction de données","sub_title":"Effacement de disque irréversible, conforme NIST SP 800-88 et DoD 5220.22-M","lbl_theme":"Thème :","theme_dark":"Sombre","theme_light":"Clair","col_disk":"Disque","col_model":"Modèle","col_size":"Taille","col_serial":"N° de série","col_health":"État","col_life":"Durée de vie","col_hours":"Heures","col_temp":"Temp.","btn_uefi":"Redémarrer dans les paramètres UEFI/BIOS","lbl_method":"Méthode d\u0027effacement :","y0":"NIST SP 800-88 Clear  -  Passe unique 0x00 (RECOMMANDÉ, suffisant pour les disques modernes)","y1":"Passe unique de données aléatoires cryptographiques","y2":"DoD 5220.22-M  -  3 passes (0x00 / 0xFF / aléatoire) + vérification","y3":"Avancé  -  7 passes (type VSITR, très lent)","chk_verify":"Vérifier après l\u0027effacement (relire le disque et contrôler)","chk_format":"Rendre le disque utilisable à la fin (créer une partition + formatage rapide)","chk_report":"Enregistrer un rapport de destruction de données (certificat) dans le dossier des rapports","chk_pdf":"Créer aussi un certificat PDF (avec code de vérification ; fonctionne avec l\u0027option de rapport)","chk_sound":"Émettre un son et faire clignoter la fenêtre à la fin","btn_refresh":"Actualiser la liste","btn_speed":"Test de vitesse","btn_trace":"Analyse des traces de données","btn_surface":"Test de surface","btn_wipe":"EFFACEMENT SÉCURISÉ","btn_cancel":"Annuler","status_ready":"Prêt. Sélectionnez le(s) disque(s) à effacer (maintenez Ctrl pour en sélectionner plusieurs).","confirm_title":"Confirmer par saisie","confirm_text":"Par sécurité, tapez ERASE en majuscules dans le champ ci-dessous pour continuer :","btn_back":"Retour","btn_startwipe":"DÉMARRER L\u0027EFFACEMENT","ready_log":"Strix Disk Cleaner v2.3 est prêt. Les capacités matérielles et les données d\u0027état (SMART) sont interrogées automatiquement lorsque vous sélectionnez un disque.","protect_log":"BOUCLIER DE PROTECTION ACTIF : le disque contenant {0} et tous les disques de démarrage/système ne peuvent jamais être ciblés ; les vérifications d\u0027identité sont répétées pendant l\u0027effacement.","first_disk_select":"Veuillez d\u0027abord sélectionner un disque dans la liste.","protect_block_log":"BOUCLIER DE PROTECTION BLOQUÉ : {0}","protect_block_msg":"BOUCLIER DE PROTECTION activé :\n\n{0}\n\nCe disque ne peut jamais être effacé.","protect_block_title":"Strix Disk Cleaner - Protection du disque système","summary_start":"TOUTES LES DONNÉES DES {0} DISQUE(S) SUIVANT(S) SERONT DÉFINITIVEMENT DÉTRUITES :","summary_disk":"  Disque {0} : {1}  |  {2}  |  {3} ({4})  |  N° de série : {5}","summary_method":"Méthode : {0}","summary_final":"Cette action est IRRÉVERSIBLE. Continuer ?","final_warning_title":"DERNIER AVERTISSEMENT","confirm_none_log":"Opération annulée par l\u0027utilisateur (confirmation non fournie).","cancel_question":"Voulez-vous vraiment annuler ?\nLe disque restera partiellement effacé (incohérent).","cancel_title":"Confirmation d\u0027annulation","cancel_question_read":"Voulez-vous vraiment annuler l\u0027opération de test de surface/d\u0027analyse ?\nLes données n\u0027ont pas été touchées ; l\u0027opération sera simplement interrompue.","t_speed":"Vitesse : {0}/s","t_remaining":"Temps restant est. : {0}","wipe_started_log":"Effacement sécurisé démarré pour le disque {0}. Méthode : {1}","queue_log":"{0} disques en file d\u0027attente ; ils seront effacés l\u0027un après l\u0027autre.","queue_next_log":"Passage au disque suivant de la file d\u0027attente : disque {0}...","queue_cancel_log":"Les disques restants en file d\u0027attente ont été ignorés en raison d\u0027une erreur/annulation.","done_msg":"Terminé !\n\nToutes les données de {0} disque(s) ont été détruites de façon irréversible selon la norme sélectionnée.","report_msg":"\n\nRapport(s) enregistré(s) dans le dossier des rapports.","success_title":"Strix Disk Cleaner - Succès","speed_started_log":"Test de vitesse démarré : disque {0} ({1}) - la phase de lecture est toujours sûre ; la phase d\u0027écriture utilise un fichier temporaire lorsque c\u0027est possible.","speed_phase1":"Test de vitesse : lecture séquentielle... {0}","speed_phase2":"Test de vitesse : lecture aléatoire 4K...","speed_read_summary":"Lecture : séquentielle {0}/s  |  aléatoire 4K {1:N0} IOPS (moy. {2:N1} ms)","speed_write_summary":"Écriture : séquentielle {0}/s  |  aléatoire 4K {1:N0} IOPS (moy. {2:N1} ms)","speed_write_raw_summary":"Écriture : séquentielle {0}/s  (mode brut ; phase d\u0027écriture aléatoire ignorée)","speed_phase3":"Test de vitesse : écriture séquentielle... {0}","speed_phase4":"Test de vitesse : écriture aléatoire 4K...","speed_write_file_log":"Cible du test d\u0027écriture : fichier temporaire sur {0}: (non destructif, supprimé ensuite).","speed_write_raw_question":"Ce disque n\u0027a aucun volume monté disposant de suffisamment d\u0027espace libre pour un test d\u0027écriture SÛR.\nLa vitesse d\u0027écriture ne peut être mesurée qu\u0027en ÉCRASANT les premiers {0} du disque avec des données de test - tout ce qui est stocké dans cette zone sera DÉTRUIT.\n\nContinuer avec le test d\u0027écriture brut destructif ?","speed_write_none":"Test d\u0027écriture ignoré.","speed_done_log":"Test de vitesse terminé. {0}","speed_note":"Remarque : les résultats d\u0027écriture basés sur un fichier incluent la surcharge du système de fichiers, ils peuvent donc être légèrement inférieurs à la vitesse brute du périphérique.","speed_status":"Test de vitesse terminé. Les résultats sont dans le journal.","speed_msg":"Disque {0} ({1})\n\n{2}","speed_title":"Strix Disk Cleaner - Test de vitesse","speed_error_log":"ERREUR du test de vitesse : {0}","trace_started_log":"Analyse des traces de données démarrée : disque {0} - échantillonnage en lecture seule.","trace_status":"Recherche de traces de données (lecture d\u0027échantillons aléatoires)...","trace_summary":"Échantillons : {0} blocs  |  Contenant des traces de données : {1} ({2}%)  |  Mis à zéro (vides) : {3}  |  0xFF : {4}  |  Entropie moy. : {5:N2} bits/octet","trace_note_empty":"Le disque semble en grande partie vide/mis à zéro.","trace_note_present":"Des TRACES DE DONNÉES RÉCUPÉRABLES sont présentes - un effacement sécurisé est recommandé avant la mise au rebut.","trace_note_encrypted":"Entropie élevée : les données sont peut-être chiffrées/compressées ; un effacement sécurisé reste recommandé.","trace_title":"Strix Disk Cleaner - Analyse des traces de données","trace_error_log":"ERREUR de l\u0027analyse des traces de données : {0}","surface_question":"Le test de surface lit le disque ENTIER ; pour {0}, cela peut prendre beaucoup de temps selon la vitesse du disque.\nLes données ne sont pas touchées. Démarrer ?","surface_title":"Test de surface","surface_started_log":"Test de surface démarré : disque {0} ({1}) - toute la surface sera analysée en lecture seule.","surface_ok_msg":"Test de surface terminé.\n\nAucun bloc illisible n\u0027a été trouvé - la surface semble saine.","surface_bad_msg":"Test de surface terminé.\n\nAVERTISSEMENT : {0} blocs de 64 KB illisibles ont été trouvés !\nPremiers emplacements (décalages en octets) :\n{1}\n\nCe disque ne convient pas à un stockage fiable.","pdf_ok_log":"Certificat PDF créé : {0}","pdf_html_log":"Convertisseur PDF (Edge) introuvable ; certificat HTML enregistré : {0} (ouvrez-le dans un navigateur et imprimez-le en PDF avec Ctrl+P).","pdf_error_log":"Le certificat PDF n\u0027a pas pu être créé : {0}","theme_dil_question":"L\u0027application va redémarrer pour appliquer cette modification. Continuer ?","theme_dil_title":"Redémarrage requis","busy_msg":"Ce paramètre ne peut pas être modifié pendant qu\u0027une opération est en cours.","temp_fmt":"Température : {0} C (pic : {1} C)","temp_report":"Temp. pendant l\u0027effacement  : pic de {0} C mesuré","uefi_question":"L\u0027ordinateur va redémarrer directement dans les paramètres UEFI/BIOS dans 5 secondes.\nAvez-vous enregistré vos fichiers ouverts ? (Fonctionne uniquement sur les systèmes UEFI.)","uefi_title":"Redémarrer dans l\u0027UEFI/BIOS","health_panel":"ÉTAT / SMART :","m_op_started":"Opération démarrée : disque {0} ({1}), {2} GB","m_method":"Méthode : {0}","m_protect_ok":"Bouclier de protection : identité du disque cible vérifiée - ce n\u0027est PAS le disque système, ne contient pas {0}.","m_status_partition":"Effacement de la table de partitions...","m_cleardisk_note":"Remarque : avertissement Clear-Disk ({0}) - poursuite.","m_raw_error":"L\u0027accès brut au disque n\u0027a pas pu être ouvert (erreur Win32 : {0}). Fermez les programmes utilisant le disque et réessayez.","m_status_write":"Écriture sur le disque...","m_pass_fmt":"Passe {0} / {1}  ({2})","m_pass_start":"Passe {0}/{1} démarrée (motif : {2}).","m_pass_done":"Passe {0}/{1} terminée.","m_random":"aléatoire","m_status_verify":"Vérification (relecture du disque)...","m_verification_label":"Vérification","m_dv_fail":"ÉCHEC DE LA VÉRIFICATION : le motif attendu est introuvable dans {0} blocs échantillonnés !","m_dv_ok_pattern":"RÉUSSIE ({0} points d\u0027échantillonnage vérifiés par rapport au motif)","m_dv_ok_rand":"RÉUSSIE ({0} points d\u0027échantillonnage relus ; la dernière passe était aléatoire, aucune comparaison de motif ne s\u0027applique)","m_dv_log":"Vérification : {0}","m_notdone":"Non effectuée","m_status_format":"Nouvelle préparation du disque (partition + formatage)...","m_format_log":"Création d\u0027une nouvelle partition et formatage rapide...","m_disk_ready":"Disque prêt : formaté en tant que lecteur {0}: ({1}).","m_status_trim":"Envoi de TRIM (notification des blocs libres au contrôleur)...","m_trim_start":"SSD détecté : exécution de Optimize-Volume -ReTrim...","m_trim_ok":"TRIM terminé : le contrôleur a également reçu l\u0027ordre de libérer les blocs obsolètes de sa table de mappage.","m_trim_error":"Étape TRIM ignorée : {0}","m_trim_none_partition":"Remarque : TRIM nécessite un volume ; ReTrim n\u0027a pas été appliqué car l\u0027option de préparation du disque est désactivée.","m_format_skipped":"Formatage ignoré : {0} (Vous pouvez initialiser le disque manuellement dans la Gestion des disques.)","m_report_saved":"Rapport de destruction enregistré : {0}","m_status_done":"TERMINÉ - Les données ont été détruites de façon irréversible.","m_op_ok":"Opération terminée avec succès.","m_cancel":"Opération annulée par l\u0027utilisateur. AVERTISSEMENT : le disque est peut-être partiellement effacé ; les données sont incohérentes.","m_cancel_read":"Analyse annulée par l\u0027utilisateur (les données n\u0027ont pas été touchées).","m_error":"ERREUR : {0}","m_k_boot":"PROTECTION ({0}) : le disque cible semble actuellement être le disque de DÉMARRAGE - opération arrêtée !","m_k_system":"PROTECTION ({0}) : le disque cible porte la partition SYSTÈME/EFI - opération arrêtée !","m_k_serial_match":"PROTECTION ({0}) : le numéro de série du disque cible correspond au disque système protégé - opération arrêtée !","m_k_num":"PROTECTION ({0}) : le numéro du disque cible figure dans la liste protégée - opération arrêtée !","m_k_serial_changed":"PROTECTION ({0}) : l\u0027identité du disque a CHANGÉ ! Numéro de série confirmé {1}, trouvé {2}. Les périphériques ont peut-être été renumérotés - arrêt par sécurité.","m_k_size":"PROTECTION ({0}) : la taille du disque ne correspond pas à celle confirmée (attendu {1}, trouvé {2}) - opération arrêtée.","m_k_c":"PROTECTION ({0}) : le disque cible héberge le lecteur {1} - opération arrêtée !","m_y_status":"Analyse de la surface (lecture seule)...","m_y_error":"Région illisible : à partir du décalage {0}, {1} sous-blocs de 64 KB en échec.","m_y_ok":"Test de surface terminé : aucun bloc illisible trouvé.","m_y_done":"Test de surface terminé : {0} blocs de 64 KB illisibles.","m_trim_applied":"Appliqué - blocs libres signalés au contrôleur","m_trim_notapplied":"Non appliqué","r_template":"=====================================================================\n           RAPPORT / CERTIFICAT DE DESTRUCTION DE DONNÉES\n=====================================================================\nCréé par          : Strix Disk Cleaner v2.3\nDate du rapport   : {0}\nOrdinateur        : {1}  (Utilisateur : {2})\n\n--- SUPPORT DÉTRUIT ---\nNuméro de disque  : {3}\nModèle            : {4}\nNuméro de série   : {5}\nCapacité          : {6} GB ({7} octets)\nType de support   : {8}  |  Bus : {9}\nDétecté           : {10}\nÉtat avant effac. : {11}\n\n--- MÉTHODE APPLIQUÉE ---\nNorme / Méthode   : {12}\nNombre de passes  : {13}\nTotal écrit       : {14} GB\nVérification      : {15}\nTRIM (ReTrim)     : {16}\nDurée             : {17} min {18} s\nRésultat          : SUCCÈS - chaque secteur du support a été écrasé.\n\nREMARQUE (NIST SP 800-88 Rev.1) : l\u0027écrasement fournit le niveau Clear.\nPour le niveau Purge sur support SSD/NVMe, étape supplémentaire :\n{19}\n=====================================================================","s_healthy":"Sain","s_warning":"AVERTISSEMENT","s_unhealthy":"DÉFAILLANT","s_status":"Statut : {0}","s_wear":"Usure : {0}% (durée de vie restante estimée ~{1}%)","s_wear_none":"Données d\u0027usure non communiquées","s_hours":"Temps de fonctionnement : {0:N0} heures (~{1:N0} jours)","s_temp":"Température : {0} C","s_temp_max":" (maximum observé : {0} C)","s_errors":"Erreurs : lecture {0} (non corrigibles : {1}), écriture {2} (non corrigibles : {3})","s_smart":"Prédiction de défaillance SMART : {0}","s_smart_bad":"DÉFAILLANCE PRÉVUE - SAUVEGARDEZ IMMÉDIATEMENT !","s_smart_good":"Normal (aucune défaillance prévue)","s_counter_none":"Les compteurs de fiabilité ne sont pas exposés pour ce disque/bus.","s_query_none":"Échec de l\u0027interrogation de l\u0027état (les boîtiers/ponts USB ne transmettent généralement pas les données SMART).","cert_title":"CERTIFICAT DE DESTRUCTION DE DONNÉES","cert_sub":"Destruction sécurisée de données conforme à NIST SP 800-88 Rev.1","cert_verification":"Code de vérification (SHA-256 du rapport)","cert_field_disk":"Disque","cert_field_serial":"N° de série","cert_field_capacity":"Capacité","cert_field_method":"Méthode","cert_field_dv":"Vérification","cert_field_duration":"Durée","cert_field_pc":"Ordinateur","cert_field_health":"État avant effacement","cert_field_result":"Résultat","cert_field_temp":"Température maximale","cert_result":"SUCCÈS - tous les secteurs écrasés","lbl_report_folder":"Dossier des rapports :","btn_report_folder":"Modifier...","report_folder_title":"Choisir l\u0027emplacement d\u0027enregistrement des rapports/certificats","chk_eject":"Éjecter les disques USB en toute sécurité à la fin","chk_task":"Afficher la progression de l\u0027effacement sur l\u0027icône de la barre des tâches","hpa_none":"Aucune zone cachée (HPA/DCO) : toute la capacité physique est adressable.","hpa_present":"ZONE CACHÉE DÉTECTÉE (HPA/DCO) : {0} de ce disque ({1} secteurs) est masqué au système d\u0027exploitation et ne sera PAS écrasé. Pour une destruction complète, utilisez l\u0027outil du fabricant ou un Secure Erase matériel (voir README).","hpa_query_none":"Vérification de zone cachée (HPA/DCO) non disponible sur ce bus (les ponts USB bloquent généralement les commandes ATA).","preview_title":"Contenu du disque (aperçu en lecture seule)","preview_empty":"Aucun volume / partition monté détecté sur ce disque.","preview_partition":"  {0}: {1}  |  {2} sur {3} utilisés ({4}% plein)  |  {5}","preview_partition_noletter":"  Partition {0} : {1}  (aucune lettre de lecteur)","preview_summary":"Ce disque comporte {0} partition(s), environ {1} de données au total.","preview_title_panel":"CONTENU :","smart_title":"Attributs SMART - Disque {0}","smart_col_name":"Attribut","smart_col_value":"Valeur","smart_col_worst":"Pire","smart_col_raw":"Brut","smart_col_status":"Statut","smart_none":"La table brute des attributs SMART n\u0027est pas disponible pour ce disque (pont USB ou NVMe - le résumé d\u0027état ci-dessus reste valable).","smart_btn":"Détails SMART","smart_check":"À VÉRIFIER","eject_ok":"Disque USB {0} éjecté - vous pouvez le débrancher en toute sécurité maintenant.","eject_error":"L\u0027éjection automatique a échoué ({0}) ; utilisez l\u0027icône « Retirer le périphérique en toute sécurité » de la barre d\u0027état système.","trace_note_clean":"Le disque est pratiquement vide - seules des structures de partition ont été trouvées (aucune donnée utilisateur récupérable).","lbl_language":"Langue :","already_running":"Strix Disk Cleaner est déjà en cours d\u0027exécution."},
"es":{"window_title":"Strix Disk Cleaner v2.3 - Herramienta profesional de destrucción de datos","sub_title":"Borrado de discos irreversible conforme a NIST SP 800-88 y DoD 5220.22-M","lbl_theme":"Tema:","theme_dark":"Oscuro","theme_light":"Claro","col_disk":"Disco","col_model":"Modelo","col_type":"Tipo","col_size":"Tamaño","col_serial":"N.º de serie","col_health":"Estado","col_life":"Vida útil","col_hours":"Horas","col_temp":"Temp.","btn_uefi":"Reiniciar en la configuración UEFI/BIOS","lbl_method":"Método de borrado:","y0":"NIST SP 800-88 Clear  -  Una sola pasada 0x00 (RECOMENDADO, suficiente para unidades modernas)","y1":"Una sola pasada de datos aleatorios criptográficos","y2":"DoD 5220.22-M  -  3 pasadas (0x00 / 0xFF / aleatorio) + verificación","y3":"Avanzado  -  7 pasadas (tipo VSITR, muy lento)","chk_verify":"Verificar tras el borrado (releer del disco y comprobar)","chk_format":"Dejar el disco utilizable al terminar (crear partición + formato rápido)","chk_report":"Guardar un informe de destrucción de datos (certificado) en la carpeta de informes","chk_pdf":"Crear también un certificado PDF (con código de verificación; funciona con la opción de informe)","chk_sound":"Reproducir un sonido y hacer parpadear la ventana al finalizar","btn_refresh":"Actualizar lista","btn_speed":"Prueba de velocidad","btn_trace":"Análisis de rastros de datos","btn_surface":"Prueba de superficie","btn_wipe":"BORRADO SEGURO","btn_cancel":"Cancelar","status_ready":"Listo. Seleccione el disco o discos que desea borrar (mantenga Ctrl para seleccionar varios).","confirm_title":"Confirmar escribiendo","confirm_text":"Por seguridad, escriba ERASE en mayúsculas en el cuadro de abajo para continuar:","btn_back":"Atrás","btn_startwipe":"INICIAR BORRADO","ready_log":"Strix Disk Cleaner v2.3 listo. Las capacidades del hardware y los datos de estado (SMART) se consultan automáticamente al seleccionar un disco.","protect_log":"ESCUDO DE PROTECCIÓN ACTIVO: el disco que contiene {0} y todos los discos de arranque/sistema nunca pueden seleccionarse como destino; las comprobaciones de identidad se repiten durante el borrado.","first_disk_select":"Seleccione primero un disco de la lista.","protect_block_log":"ESCUDO DE PROTECCIÓN BLOQUEADO: {0}","protect_block_msg":"ESCUDO DE PROTECCIÓN activado:\n\n{0}\n\nEste disco nunca puede borrarse.","protect_block_title":"Strix Disk Cleaner - Protección del disco del sistema","summary_start":"TODOS LOS DATOS DE LOS SIGUIENTES {0} DISCO(S) SE DESTRUIRÁN DE FORMA PERMANENTE:","summary_disk":"  Disco {0}: {1}  |  {2}  |  {3} ({4})  |  Serie: {5}","summary_method":"Método: {0}","summary_final":"Esto NO se puede deshacer. ¿Continuar?","final_warning_title":"ADVERTENCIA FINAL","confirm_none_log":"Operación cancelada por el usuario (no se dio la confirmación).","cancel_question":"¿Seguro que desea cancelar?\nEl disco quedará parcialmente borrado (en estado incoherente).","cancel_title":"Confirmación de cancelación","cancel_question_read":"¿Seguro que desea cancelar la operación de superficie/análisis?\nLos datos no se han tocado; la operación simplemente se interrumpirá.","t_speed":"Velocidad: {0}/s","t_remaining":"Restante estimado: {0}","wipe_started_log":"Borrado seguro iniciado para el disco {0}. Método: {1}","queue_log":"{0} discos en cola; se borrarán uno tras otro.","queue_next_log":"Pasando al siguiente disco de la cola: Disco {0}...","queue_cancel_log":"Los discos restantes en cola se omitieron debido a un error/cancelación.","done_msg":"¡Listo!\n\nTodos los datos de {0} disco(s) se destruyeron de forma irreversible según el estándar seleccionado.","report_msg":"\n\nInforme(s) guardado(s) en la carpeta de informes.","success_title":"Strix Disk Cleaner - Correcto","speed_started_log":"Prueba de velocidad iniciada: Disco {0} ({1}) - la fase de lectura siempre es segura; la fase de escritura usa un archivo temporal cuando es posible.","speed_phase1":"Prueba de velocidad: lectura secuencial... {0}","speed_phase2":"Prueba de velocidad: lectura aleatoria 4K...","speed_read_summary":"Lectura : secuencial {0}/s  |  aleatoria 4K {1:N0} IOPS (media {2:N1} ms)","speed_write_summary":"Escritura: secuencial {0}/s  |  aleatoria 4K {1:N0} IOPS (media {2:N1} ms)","speed_write_raw_summary":"Escritura: secuencial {0}/s  (modo RAW; fase de escritura aleatoria omitida)","speed_phase3":"Prueba de velocidad: escritura secuencial... {0}","speed_phase4":"Prueba de velocidad: escritura aleatoria 4K...","speed_write_file_log":"Destino de la prueba de escritura: archivo temporal en {0}: (no destructivo, se elimina después).","speed_write_raw_question":"Este disco no tiene ningún volumen montado con suficiente espacio libre para una prueba de escritura SEGURA.\nLa velocidad de escritura solo puede medirse SOBRESCRIBIENDO los primeros {0} del disco con datos de prueba; lo que esté almacenado en esa zona se DESTRUIRÁ.\n\n¿Continuar con la prueba de escritura RAW destructiva?","speed_write_none":"Prueba de escritura omitida.","speed_done_log":"Prueba de velocidad finalizada. {0}","speed_note":"Nota: los resultados de escritura basados en archivo incluyen la sobrecarga del sistema de archivos, por lo que pueden aparecer ligeramente por debajo de la velocidad RAW del dispositivo.","speed_status":"Prueba de velocidad finalizada. Los resultados están en el registro.","speed_msg":"Disco {0} ({1})\n\n{2}","speed_title":"Strix Disk Cleaner - Prueba de velocidad","speed_error_log":"ERROR en la prueba de velocidad: {0}","trace_started_log":"Análisis de rastros de datos iniciado: Disco {0} - muestreo de solo lectura.","trace_status":"Buscando rastros de datos (leyendo muestras aleatorias)...","trace_summary":"Muestras: {0} bloques  |  Con rastros de datos: {1} ({2}%)  |  A cero (en blanco): {3}  |  0xFF: {4}  |  Entropía media: {5:N2} bits/byte","trace_note_empty":"El disco parece estar en gran parte en blanco/a cero.","trace_note_present":"Hay RASTROS DE DATOS RECUPERABLES presentes; se recomienda un borrado seguro antes de desecharlo.","trace_note_encrypted":"Entropía alta: los datos podrían estar cifrados/comprimidos; aun así se recomienda un borrado seguro.","trace_title":"Strix Disk Cleaner - Análisis de rastros de datos","trace_error_log":"ERROR en el análisis de rastros de datos: {0}","surface_question":"La prueba de superficie lee el disco COMPLETO; para {0} esto puede tardar mucho tiempo según la velocidad del disco.\nLos datos no se tocan. ¿Iniciar?","surface_title":"Prueba de superficie","surface_started_log":"Prueba de superficie iniciada: Disco {0} ({1}) - se analizará toda la superficie en modo de solo lectura.","surface_ok_msg":"Prueba de superficie finalizada.\n\nNo se encontraron bloques ilegibles; la superficie parece estar en buen estado.","surface_bad_msg":"Prueba de superficie finalizada.\n\nADVERTENCIA: ¡se encontraron {0} bloques ilegibles de 64 KB!\nPrimeras ubicaciones (desplazamientos en bytes):\n{1}\n\nEste disco no es apto para un almacenamiento fiable.","pdf_ok_log":"Certificado PDF creado: {0}","pdf_html_log":"No se encontró el convertidor de PDF (Edge); se guardó el certificado HTML: {0} (ábralo en un navegador e imprímalo en PDF con Ctrl+P).","pdf_error_log":"No se pudo crear el certificado PDF: {0}","theme_dil_question":"La aplicación se reiniciará para aplicar este cambio. ¿Continuar?","theme_dil_title":"Reinicio necesario","busy_msg":"Esta opción no puede cambiarse mientras una operación está en curso.","temp_fmt":"Temperatura: {0} C (pico: {1} C)","temp_report":"Temp. durante el borrado : pico de {0} C medido","uefi_question":"El equipo se reiniciará directamente en la configuración UEFI/BIOS en 5 segundos.\n¿Ha guardado los archivos abiertos? (Funciona solo en sistemas UEFI.)","uefi_title":"Reiniciar en UEFI/BIOS","health_panel":"ESTADO / SMART:","m_op_started":"Operación iniciada: Disco {0} ({1}), {2} GB","m_method":"Método: {0}","m_protect_ok":"Escudo de protección: identidad del disco de destino verificada; NO es el disco del sistema, no contiene {0}.","m_status_partition":"Borrando la tabla de particiones...","m_cleardisk_note":"Nota: advertencia de Clear-Disk ({0}) - continuando.","m_raw_error":"No se pudo abrir el acceso RAW al disco (error de Win32: {0}). Cierre los programas que usan el disco e inténtelo de nuevo.","m_status_write":"Escribiendo en el disco...","m_pass_fmt":"Pasada {0} / {1}  ({2})","m_pass_start":"Pasada {0}/{1} iniciada (patrón: {2}).","m_pass_done":"Pasada {0}/{1} completada.","m_random":"aleatorio","m_status_verify":"Verificando (releyendo del disco)...","m_verification_label":"Verificación","m_dv_fail":"VERIFICACIÓN FALLIDA: ¡el patrón esperado no se encontró en {0} bloques muestreados!","m_dv_ok_pattern":"SUPERADA ({0} puntos de muestra verificados frente al patrón)","m_dv_ok_rand":"SUPERADA ({0} puntos de muestra releídos; la última pasada fue aleatoria, por lo que no se aplica comparación de patrón)","m_dv_log":"Verificación: {0}","m_notdone":"No realizada","m_status_format":"Preparando el disco de nuevo (partición + formato)...","m_format_log":"Creando una nueva partición y aplicando formato rápido...","m_disk_ready":"Disco listo: formateado como unidad {0}: ({1}).","m_status_trim":"Enviando TRIM (notificando al controlador los bloques libres)...","m_trim_start":"SSD detectado: ejecutando Optimize-Volume -ReTrim...","m_trim_ok":"TRIM finalizado: también se indicó al controlador que liberase los bloques obsoletos de su tabla de asignación.","m_trim_error":"Paso de TRIM omitido: {0}","m_trim_none_partition":"Nota: TRIM necesita un volumen; no se aplicó ReTrim porque la opción de preparar el disco está desactivada.","m_format_skipped":"Formato omitido: {0} (Puede inicializar el disco manualmente en Administración de discos.)","m_report_saved":"Informe de destrucción guardado: {0}","m_status_done":"COMPLETADO - Los datos se han destruido de forma irreversible.","m_op_ok":"Operación completada correctamente.","m_cancel":"Operación cancelada por el usuario. ADVERTENCIA: el disco puede estar parcialmente borrado; los datos son incoherentes.","m_cancel_read":"Análisis cancelado por el usuario (los datos no se tocaron).","m_k_boot":"PROTECCIÓN ({0}): ¡el disco de destino parece ser actualmente el disco de ARRANQUE - operación detenida!","m_k_system":"PROTECCIÓN ({0}): ¡el disco de destino contiene la partición SYSTEM/EFI - operación detenida!","m_k_serial_match":"PROTECCIÓN ({0}): ¡el número de serie del disco de destino coincide con el disco del sistema protegido - operación detenida!","m_k_num":"PROTECCIÓN ({0}): ¡el número del disco de destino está en la lista de protegidos - operación detenida!","m_k_serial_changed":"PROTECCIÓN ({0}): ¡la identidad del disco CAMBIÓ! Serie confirmada {1}, encontrada {2}. Es posible que los dispositivos se hayan renumerado - detenido por seguridad.","m_k_size":"PROTECCIÓN ({0}): el tamaño del disco no coincide con el confirmado (esperado {1}, encontrado {2}) - operación detenida.","m_k_c":"PROTECCIÓN ({0}): ¡el disco de destino aloja la unidad {1} - operación detenida!","m_y_status":"Analizando la superficie (solo lectura)...","m_y_error":"Región ilegible: a partir del desplazamiento {0}, {1} subbloques de 64 KB fallidos.","m_y_ok":"Prueba de superficie finalizada: no se encontraron bloques ilegibles.","m_y_done":"Prueba de superficie finalizada: {0} bloques ilegibles de 64 KB.","m_trim_applied":"Aplicado - bloques libres notificados al controlador","m_trim_notapplied":"No aplicado","r_template":"=====================================================================\n                INFORME / CERTIFICADO DE DESTRUCCIÓN DE DATOS\n=====================================================================\nCreado por          : Strix Disk Cleaner v2.3\nFecha del informe   : {0}\nEquipo              : {1}  (Usuario: {2})\n\n--- SOPORTE DESTRUIDO ---\nNúmero de disco     : {3}\nModelo              : {4}\nNúmero de serie     : {5}\nCapacidad           : {6} GB ({7} bytes)\nTipo de soporte     : {8}  |  Bus: {9}\nDetectado           : {10}\nEstado previo       : {11}\n\n--- MÉTODO APLICADO ---\nEstándar / Método   : {12}\nNúm. de pasadas     : {13}\nTotal escrito       : {14} GB\nVerificación        : {15}\nTRIM (ReTrim)       : {16}\nDuración            : {17} min {18} s\nResultado           : CORRECTO - se sobrescribió cada sector del soporte.\n\nNOTA (NIST SP 800-88 Rev.1): La sobrescritura proporciona el nivel Clear.\nPara el nivel Purge en soportes SSD/NVMe, paso adicional:\n{19}\n=====================================================================","s_healthy":"En buen estado","s_warning":"ADVERTENCIA","s_unhealthy":"EN MAL ESTADO","s_status":"Estado: {0}","s_wear":"Desgaste: {0}% (vida útil restante estimada ~{1}%)","s_wear_none":"No se informan datos de desgaste","s_hours":"Encendido: {0:N0} horas (~{1:N0} días)","s_temp":"Temperatura: {0} C","s_temp_max":" (máxima registrada: {0} C)","s_errors":"Errores: lectura {0} (no corregibles: {1}), escritura {2} (no corregibles: {3})","s_smart":"Predicción de fallo SMART: {0}","s_smart_bad":"FALLO PREVISTO - ¡HAGA UNA COPIA DE SEGURIDAD AHORA!","s_smart_good":"Normal (no se prevé ningún fallo)","s_counter_none":"Los contadores de fiabilidad no están disponibles para este disco/bus.","s_query_none":"La consulta de estado falló (las carcasas/puentes USB normalmente no transmiten los datos SMART).","cert_title":"CERTIFICADO DE DESTRUCCIÓN DE DATOS","cert_sub":"Destrucción segura de datos conforme a NIST SP 800-88 Rev.1","cert_verification":"Código de verificación (SHA-256 del informe)","cert_field_disk":"Disco","cert_field_serial":"N.º de serie","cert_field_capacity":"Capacidad","cert_field_method":"Método","cert_field_pass":"Pasadas","cert_field_dv":"Verificación","cert_field_duration":"Duración","cert_field_date":"Fecha","cert_field_pc":"Equipo","cert_field_health":"Estado previo al borrado","cert_field_result":"Resultado","cert_field_temp":"Temperatura máxima","cert_result":"CORRECTO - todos los sectores sobrescritos","lbl_report_folder":"Carpeta de informes:","btn_report_folder":"Cambiar...","report_folder_title":"Elija dónde se guardan los informes/certificados","chk_eject":"Expulsar de forma segura los discos USB al finalizar","chk_task":"Mostrar el progreso del borrado en el icono de la barra de tareas","hpa_none":"Sin área oculta (HPA/DCO): toda la capacidad física es direccionable.","hpa_present":"ÁREA OCULTA DETECTADA (HPA/DCO): {0} de este disco ({1} sectores) está oculto para el sistema operativo y NO se sobrescribirá. Para una destrucción completa, use la herramienta del fabricante o un Secure Erase por hardware (consulte el README).","hpa_query_none":"La comprobación de área oculta (HPA/DCO) no está disponible en este bus (los puentes USB suelen bloquear los comandos ATA).","preview_title":"Contenido del disco (vista previa de solo lectura)","preview_empty":"No se detectaron volúmenes/particiones montados en este disco.","preview_partition":"  {0}: {1}  |  {2} de {3} usados ({4}% lleno)  |  {5}","preview_partition_noletter":"  Partición {0}: {1}  (sin letra de unidad)","preview_summary":"Este disco tiene {0} partición(es), con aproximadamente {1} de datos en total.","preview_title_panel":"CONTENIDO:","smart_title":"Atributos SMART - Disco {0}","smart_col_name":"Atributo","smart_col_value":"Valor","smart_col_worst":"Peor","smart_col_raw":"Bruto","smart_col_status":"Estado","smart_none":"La tabla de atributos SMART en bruto no está disponible para este disco (puente USB o NVMe; el resumen de estado anterior sigue siendo válido).","smart_btn":"Detalles de SMART","smart_ok":"Correcto","smart_check":"REVISAR","eject_ok":"Disco USB {0} expulsado; ya puede desconectarlo de forma segura.","eject_error":"La expulsión automática falló ({0}); use el icono \"Quitar hardware de forma segura\" de la bandeja del sistema.","trace_note_clean":"El disco está prácticamente en blanco; solo se encontraron estructuras de partición (sin datos de usuario recuperables).","lbl_language":"Idioma:","already_running":"Strix Disk Cleaner ya se está ejecutando."},
"it":{"window_title":"Strix Disk Cleaner v2.3 - Strumento professionale per la distruzione dei dati","sub_title":"Cancellazione irreversibile del disco conforme a NIST SP 800-88 e DoD 5220.22-M","lbl_theme":"Tema:","theme_dark":"Scuro","theme_light":"Chiaro","col_disk":"Disco","col_model":"Modello","col_type":"Tipo","col_size":"Dimensione","col_serial":"N. di serie","col_health":"Stato","col_life":"Durata","col_hours":"Ore","btn_uefi":"Riavvia nelle impostazioni UEFI/BIOS","lbl_method":"Metodo di cancellazione:","y0":"NIST SP 800-88 Clear  -  Passaggio singolo 0x00 (CONSIGLIATO, sufficiente per i dischi moderni)","y1":"Passaggio singolo con dati casuali crittografici","y2":"DoD 5220.22-M  -  3 passaggi (0x00 / 0xFF / casuale) + verifica","y3":"Avanzato  -  7 passaggi (tipo VSITR, molto lento)","chk_verify":"Verifica dopo la cancellazione (rilegge dal disco e controlla)","chk_format":"Rendi il disco utilizzabile al termine (crea partizione + formattazione rapida)","chk_report":"Salva un rapporto di distruzione dei dati (certificato) nella cartella dei rapporti","chk_pdf":"Crea anche un certificato PDF (con codice di verifica; funziona con l\u0027opzione rapporto)","chk_sound":"Riproduci un suono e fai lampeggiare la finestra al termine","btn_refresh":"Aggiorna elenco","btn_speed":"Test di velocità","btn_trace":"Scansione tracce di dati","btn_surface":"Test della superficie","btn_wipe":"CANCELLAZIONE SICURA","btn_cancel":"Annulla","status_ready":"Pronto. Seleziona il disco o i dischi da cancellare (tieni premuto Ctrl per selezionarne più di uno).","confirm_title":"Conferma digitando","confirm_text":"Per sicurezza, digita ERASE in lettere maiuscole nella casella sottostante per continuare:","btn_back":"Indietro","btn_startwipe":"AVVIA CANCELLAZIONE","ready_log":"Strix Disk Cleaner v2.3 pronto. Le funzionalità hardware e i dati sullo stato (SMART) vengono interrogati automaticamente quando selezioni un disco.","protect_log":"SCUDO DI PROTEZIONE ATTIVO: il disco che contiene {0} e tutti i dischi di avvio/di sistema non possono mai essere selezionati; i controlli di identità vengono ripetuti durante la cancellazione.","first_disk_select":"Seleziona prima un disco dall\u0027elenco.","protect_block_log":"SCUDO DI PROTEZIONE HA BLOCCATO: {0}","protect_block_msg":"SCUDO DI PROTEZIONE attivato:\n\n{0}\n\nQuesto disco non può mai essere cancellato.","protect_block_title":"Strix Disk Cleaner - Protezione del disco di sistema","summary_start":"TUTTI I DATI SUI SEGUENTI {0} DISCHI VERRANNO DISTRUTTI IN MODO PERMANENTE:","summary_disk":"  Disco {0}: {1}  |  {2}  |  {3} ({4})  |  Serie: {5}","summary_method":"Metodo: {0}","summary_final":"L\u0027operazione NON può essere annullata. Continuare?","final_warning_title":"AVVISO FINALE","confirm_none_log":"Operazione annullata dall\u0027utente (conferma non fornita).","cancel_question":"Sei sicuro di voler annullare?\nIl disco rimarrà parzialmente cancellato (in stato incoerente).","cancel_title":"Conferma annullamento","cancel_question_read":"Sei sicuro di voler annullare l\u0027operazione di superficie/scansione?\nI dati non sono stati toccati; l\u0027operazione verrà semplicemente interrotta.","t_speed":"Velocità: {0}/s","t_remaining":"Tempo residuo stimato: {0}","wipe_started_log":"Cancellazione sicura avviata per il disco {0}. Metodo: {1}","queue_log":"{0} dischi in coda; verranno cancellati uno dopo l\u0027altro.","queue_next_log":"Passaggio al disco successivo nella coda: Disco {0}...","queue_cancel_log":"I dischi rimanenti in coda sono stati saltati a causa di un errore/annullamento.","done_msg":"Fatto!\n\nTutti i dati su {0} dischi sono stati distrutti in modo irreversibile secondo lo standard selezionato.","report_msg":"\n\nRapporto/i salvato/i nella cartella dei rapporti.","success_title":"Strix Disk Cleaner - Operazione riuscita","speed_started_log":"Test di velocità avviato: Disco {0} ({1}) - la fase di lettura è sempre sicura; la fase di scrittura usa un file temporaneo quando possibile.","speed_phase1":"Test di velocità: lettura sequenziale... {0}","speed_phase2":"Test di velocità: lettura casuale 4K...","speed_read_summary":"Lettura : sequenziale {0}/s  |  casuale 4K {1:N0} IOPS (media {2:N1} ms)","speed_write_summary":"Scrittura: sequenziale {0}/s  |  casuale 4K {1:N0} IOPS (media {2:N1} ms)","speed_write_raw_summary":"Scrittura: sequenziale {0}/s  (modalità raw; fase di scrittura casuale saltata)","speed_phase3":"Test di velocità: scrittura sequenziale... {0}","speed_phase4":"Test di velocità: scrittura casuale 4K...","speed_write_file_log":"Destinazione del test di scrittura: file temporaneo su {0}: (non distruttivo, eliminato al termine).","speed_write_raw_question":"Questo disco non ha alcun volume montato con spazio libero sufficiente per un test di scrittura SICURO.\nLa velocità di scrittura può essere misurata solo SOVRASCRIVENDO i primi {0} del disco con dati di prova - qualsiasi contenuto in quell\u0027area verrà DISTRUTTO.\n\nProcedere con il test di scrittura raw distruttivo?","speed_write_none":"Test di scrittura saltato.","speed_done_log":"Test di velocità terminato. {0}","speed_note":"Nota: i risultati di scrittura basati su file includono il sovraccarico del filesystem, quindi possono risultare leggermente inferiori alla velocità raw del dispositivo.","speed_status":"Test di velocità terminato. I risultati sono nel registro.","speed_msg":"Disco {0} ({1})\n\n{2}","speed_title":"Strix Disk Cleaner - Test di velocità","speed_error_log":"ERRORE del test di velocità: {0}","trace_started_log":"Scansione tracce di dati avviata: Disco {0} - campionamento in sola lettura.","trace_status":"Ricerca di tracce di dati (lettura di campioni casuali)...","trace_summary":"Campioni: {0} blocchi  |  Contenenti tracce di dati: {1} ({2}%)  |  Azzerati (vuoti): {3}  |  0xFF: {4}  |  Entropia media: {5:N2} bit/byte","trace_note_empty":"Il disco risulta in gran parte vuoto/azzerato.","trace_note_present":"Sono presenti TRACCE DI DATI RECUPERABILI - si consiglia una cancellazione sicura prima dello smaltimento.","trace_note_encrypted":"Entropia elevata: i dati potrebbero essere crittografati/compressi; si consiglia comunque una cancellazione sicura.","trace_title":"Strix Disk Cleaner - Scansione tracce di dati","trace_error_log":"ERRORE della scansione tracce di dati: {0}","surface_question":"Il test della superficie legge l\u0027INTERO disco; per {0} può richiedere molto tempo a seconda della velocità del disco.\nI dati non vengono toccati. Avviare?","surface_title":"Test della superficie","surface_started_log":"Test della superficie avviato: Disco {0} ({1}) - l\u0027intera superficie verrà scansionata in sola lettura.","surface_ok_msg":"Test della superficie terminato.\n\nNessun blocco illeggibile trovato - la superficie sembra integra.","surface_bad_msg":"Test della superficie terminato.\n\nATTENZIONE: sono stati trovati {0} blocchi illeggibili da 64 KB!\nPrime posizioni (offset in byte):\n{1}\n\nQuesto disco non è adatto a un\u0027archiviazione affidabile.","pdf_ok_log":"Certificato PDF creato: {0}","pdf_html_log":"Convertitore PDF (Edge) non trovato; certificato HTML salvato: {0} (aprilo in un browser e stampalo in PDF con Ctrl+P).","pdf_error_log":"Impossibile creare il certificato PDF: {0}","theme_dil_question":"L\u0027applicazione verrà riavviata per applicare questa modifica. Continuare?","theme_dil_title":"Riavvio richiesto","busy_msg":"Questa impostazione non può essere modificata mentre è in corso un\u0027operazione.","temp_fmt":"Temperatura: {0} C (picco: {1} C)","temp_report":"Temp durante cancellazione  : picco {0} C misurato","uefi_question":"Il computer verrà riavviato direttamente nelle impostazioni UEFI/BIOS tra 5 secondi.\nHai salvato i file aperti? (Funziona solo sui sistemi UEFI.)","uefi_title":"Riavvia in UEFI/BIOS","health_panel":"STATO / SMART:","m_op_started":"Operazione avviata: Disco {0} ({1}), {2} GB","m_method":"Metodo: {0}","m_protect_ok":"Scudo di protezione: identità del disco di destinazione verificata - NON è il disco di sistema, non contiene {0}.","m_status_partition":"Cancellazione della tabella delle partizioni...","m_cleardisk_note":"Nota: avviso di Clear-Disk ({0}) - proseguimento.","m_raw_error":"Impossibile aprire l\u0027accesso raw al disco (errore Win32: {0}). Chiudi i programmi che utilizzano il disco e riprova.","m_status_write":"Scrittura sul disco...","m_pass_fmt":"Passaggio {0} / {1}  ({2})","m_pass_start":"Passaggio {0}/{1} avviato (pattern: {2}).","m_pass_done":"Passaggio {0}/{1} completato.","m_random":"casuale","m_status_verify":"Verifica in corso (rilettura dal disco)...","m_verification_label":"Verifica","m_dv_fail":"VERIFICA NON RIUSCITA: pattern atteso non trovato in {0} blocchi campionati!","m_dv_ok_pattern":"SUPERATA ({0} punti campione verificati rispetto al pattern)","m_dv_ok_rand":"SUPERATA ({0} punti campione riletti; l\u0027ultimo passaggio era casuale quindi non si applica alcun confronto di pattern)","m_dv_log":"Verifica: {0}","m_notdone":"Non eseguita","m_status_format":"Nuova preparazione del disco (partizione + formattazione)...","m_format_log":"Creazione di una nuova partizione e formattazione rapida...","m_disk_ready":"Disco pronto: formattato come unità {0}: ({1}).","m_status_trim":"Invio del comando TRIM (notifica al controller dei blocchi liberi)...","m_trim_start":"SSD rilevato: esecuzione di Optimize-Volume -ReTrim...","m_trim_ok":"TRIM completato: al controller è stato indicato di rilasciare anche i blocchi obsoleti nella sua tabella di mappatura.","m_trim_error":"Fase TRIM saltata: {0}","m_trim_none_partition":"Nota: TRIM richiede un volume; ReTrim non è stato applicato perché l\u0027opzione di preparazione del disco è disattivata.","m_format_skipped":"Formattazione saltata: {0} (Puoi inizializzare il disco manualmente in Gestione disco.)","m_report_saved":"Rapporto di distruzione salvato: {0}","m_status_done":"COMPLETATO - I dati sono stati distrutti in modo irreversibile.","m_op_ok":"Operazione completata con successo.","m_cancel":"Operazione annullata dall\u0027utente. ATTENZIONE: il disco potrebbe essere parzialmente cancellato; i dati sono in stato incoerente.","m_cancel_read":"Scansione annullata dall\u0027utente (i dati non sono stati toccati).","m_error":"ERRORE: {0}","m_k_boot":"PROTEZIONE ({0}): il disco di destinazione risulta attualmente essere il disco di AVVIO - operazione interrotta!","m_k_system":"PROTEZIONE ({0}): il disco di destinazione contiene la partizione di SISTEMA/EFI - operazione interrotta!","m_k_serial_match":"PROTEZIONE ({0}): il numero di serie del disco di destinazione corrisponde a quello del disco di sistema protetto - operazione interrotta!","m_k_num":"PROTEZIONE ({0}): il numero del disco di destinazione è nell\u0027elenco protetto - operazione interrotta!","m_k_serial_changed":"PROTEZIONE ({0}): l\u0027identità del disco è CAMBIATA! Numero di serie confermato {1}, trovato {2}. I dispositivi potrebbero essere stati rinumerati - interrotto per sicurezza.","m_k_size":"PROTEZIONE ({0}): la dimensione del disco non corrisponde a quella confermata (attesa {1}, trovata {2}) - operazione interrotta.","m_k_c":"PROTEZIONE ({0}): il disco di destinazione ospita l\u0027unità {1} - operazione interrotta!","m_y_status":"Scansione della superficie (sola lettura)...","m_y_error":"Regione illeggibile: a partire dall\u0027offset {0}, {1} sotto-blocchi da 64 KB non riusciti.","m_y_ok":"Test della superficie terminato: nessun blocco illeggibile trovato.","m_y_done":"Test della superficie terminato: {0} blocchi illeggibili da 64 KB.","m_trim_applied":"Applicato - blocchi liberi segnalati al controller","m_trim_notapplied":"Non applicato","r_template":"=====================================================================\n                RAPPORTO / CERTIFICATO DI DISTRUZIONE DEI DATI\n=====================================================================\nCreato da         : Strix Disk Cleaner v2.3\nData rapporto     : {0}\nComputer          : {1}  (Utente: {2})\n\n--- SUPPORTO DISTRUTTO ---\nNumero disco      : {3}\nModello           : {4}\nNumero di serie   : {5}\nCapacità          : {6} GB ({7} byte)\nTipo di supporto  : {8}  |  Bus: {9}\nRilevato          : {10}\nStato pre-cancell.: {11}\n\n--- METODO APPLICATO ---\nStandard / Metodo : {12}\nNumero passaggi   : {13}\nTotale scritto    : {14} GB\nVerifica          : {15}\nTRIM (ReTrim)     : {16}\nDurata            : {17} min {18} s\nRisultato         : SUCCESSO - ogni settore del supporto è stato sovrascritto.\n\nNOTA (NIST SP 800-88 Rev.1): la sovrascrittura fornisce il livello Clear.\nPer il livello Purge sui supporti SSD/NVMe, passaggio aggiuntivo:\n{19}\n=====================================================================","s_healthy":"Integro","s_warning":"ATTENZIONE","s_unhealthy":"NON INTEGRO","s_status":"Stato: {0}","s_wear":"Usura: {0}% (durata residua stimata ~{1}%)","s_wear_none":"Dati sull\u0027usura non riportati","s_hours":"Accensione: {0:N0} ore (~{1:N0} giorni)","s_temp":"Temperatura: {0} C","s_temp_max":" (massima rilevata: {0} C)","s_errors":"Errori: lettura {0} (non correggibili: {1}), scrittura {2} (non correggibili: {3})","s_smart":"Previsione di guasto SMART: {0}","s_smart_bad":"GUASTO PREVISTO - ESEGUI SUBITO IL BACKUP!","s_smart_good":"Normale (nessun guasto previsto)","s_counter_none":"I contatori di affidabilità non sono disponibili per questo disco/bus.","s_query_none":"Interrogazione dello stato non riuscita (i box/bridge USB di solito non trasmettono i dati SMART).","cert_title":"CERTIFICATO DI DISTRUZIONE DEI DATI","cert_sub":"Distruzione sicura dei dati conforme a NIST SP 800-88 Rev.1","cert_verification":"Codice di verifica (SHA-256 del rapporto)","cert_field_disk":"Disco","cert_field_serial":"N. di serie","cert_field_capacity":"Capacità","cert_field_method":"Metodo","cert_field_pass":"Passaggi","cert_field_dv":"Verifica","cert_field_duration":"Durata","cert_field_date":"Data","cert_field_health":"Stato pre-cancellazione","cert_field_result":"Risultato","cert_field_temp":"Temperatura di picco","cert_result":"SUCCESSO - tutti i settori sovrascritti","lbl_report_folder":"Cartella dei rapporti:","btn_report_folder":"Cambia...","report_folder_title":"Scegli dove salvare i rapporti/certificati","chk_eject":"Espelli in sicurezza i dischi USB al termine","chk_task":"Mostra l\u0027avanzamento della cancellazione sull\u0027icona della barra delle applicazioni","hpa_none":"Nessuna area nascosta (HPA/DCO): l\u0027intera capacità fisica è indirizzabile.","hpa_present":"AREA NASCOSTA RILEVATA (HPA/DCO): {0} di questo disco ({1} settori) è nascosto al sistema operativo e NON verrà sovrascritto. Per una distruzione completa usa lo strumento del produttore o un Secure Erase hardware (vedi README).","hpa_query_none":"Il controllo dell\u0027area nascosta (HPA/DCO) non è disponibile su questo bus (i bridge USB di solito bloccano i comandi ATA).","preview_title":"Contenuto del disco (anteprima in sola lettura)","preview_empty":"Nessun volume / partizione montato rilevato su questo disco.","preview_partition":"  {0}: {1}  |  {2} di {3} utilizzati ({4}% pieno)  |  {5}","preview_partition_noletter":"  Partizione {0}: {1}  (nessuna lettera di unità)","preview_summary":"Questo disco ha {0} partizioni, circa {1} di dati in totale.","preview_title_panel":"CONTENUTO:","smart_title":"Attributi SMART - Disco {0}","smart_col_name":"Attributo","smart_col_value":"Valore","smart_col_worst":"Peggiore","smart_col_raw":"Grezzo","smart_col_status":"Stato","smart_none":"La tabella grezza degli attributi SMART non è disponibile per questo disco (bridge USB o NVMe - il riepilogo dello stato qui sopra rimane comunque valido).","smart_btn":"Dettagli SMART","smart_check":"CONTROLLA","eject_ok":"Disco USB {0} espulso - ora puoi scollegarlo in sicurezza.","eject_error":"Espulsione automatica non riuscita ({0}); usa l\u0027icona \"Rimozione sicura dell\u0027hardware\" nell\u0027area di notifica.","trace_note_clean":"Il disco è sostanzialmente vuoto - sono state trovate solo strutture di partizione (nessun dato utente recuperabile).","lbl_language":"Lingua:","already_running":"Strix Disk Cleaner è già in esecuzione."},
"pt-BR":{"window_title":"Strix Disk Cleaner v2.3 - Ferramenta Profissional de Destruição de Dados","sub_title":"Limpeza de disco irreversível, em conformidade com NIST SP 800-88 e DoD 5220.22-M","lbl_theme":"Tema:","theme_dark":"Escuro","theme_light":"Claro","col_disk":"Disco","col_model":"Modelo","col_type":"Tipo","col_bus":"Barramento","col_size":"Tamanho","col_serial":"Nº de Série","col_health":"Integridade","col_life":"Vida útil","col_hours":"Horas","btn_uefi":"Reiniciar nas Configurações UEFI/BIOS","lbl_method":"Método de Limpeza:","y0":"NIST SP 800-88 Clear  -  Passagem única 0x00 (RECOMENDADO, suficiente para discos modernos)","y1":"Passagem única com dados aleatórios criptográficos","y2":"DoD 5220.22-M  -  3 passagens (0x00 / 0xFF / aleatório) + verificação","y3":"Avançado  -  7 passagens (semelhante a VSITR, muito lento)","chk_verify":"Verificar após a limpeza (reler o disco e conferir)","chk_format":"Deixar o disco utilizável ao concluir (criar partição + formatação rápida)","chk_report":"Salvar um Relatório de Destruição de Dados (certificado) na pasta de relatórios","chk_pdf":"Também criar um certificado em PDF (com código de verificação; funciona com a opção de relatório)","chk_sound":"Reproduzir um som e piscar a janela ao terminar","btn_refresh":"Atualizar Lista","btn_speed":"Teste de Velocidade","btn_trace":"Varredura de Vestígios de Dados","btn_surface":"Teste de Superfície","btn_wipe":"APAGAMENTO SEGURO","btn_cancel":"Cancelar","status_ready":"Pronto. Selecione o(s) disco(s) a limpar (segure Ctrl para selecionar vários).","confirm_title":"Confirmar Digitando","confirm_text":"Por segurança, digite ERASE em letras maiúsculas na caixa abaixo para continuar:","btn_back":"Voltar","btn_startwipe":"INICIAR LIMPEZA","ready_log":"Strix Disk Cleaner v2.3 pronto. Os recursos de hardware e os dados de integridade (SMART) são consultados automaticamente ao selecionar um disco.","protect_log":"ESCUDO DE PROTEÇÃO ATIVO: o disco que contém {0} e todos os discos de boot/sistema nunca podem ser selecionados; as verificações de identidade são repetidas durante a limpeza.","first_disk_select":"Selecione primeiro um disco na lista.","protect_block_log":"ESCUDO DE PROTEÇÃO BLOQUEOU: {0}","protect_block_msg":"ESCUDO DE PROTEÇÃO acionado:\n\n{0}\n\nEste disco nunca pode ser limpo.","protect_block_title":"Strix Disk Cleaner - Proteção do Disco do Sistema","summary_start":"TODOS OS DADOS NO(S) SEGUINTE(S) {0} DISCO(S) SERÃO DESTRUÍDOS PERMANENTEMENTE:","summary_disk":"  Disco {0}: {1}  |  {2}  |  {3} ({4})  |  Série: {5}","summary_method":"Método: {0}","summary_final":"Isto NÃO pode ser desfeito. Continuar?","final_warning_title":"AVISO FINAL","confirm_none_log":"Operação cancelada pelo usuário (confirmação não fornecida).","cancel_question":"Tem certeza de que deseja cancelar?\nO disco ficará parcialmente limpo (inconsistente).","cancel_title":"Confirmação de Cancelamento","cancel_question_read":"Tem certeza de que deseja cancelar a operação de superfície/varredura?\nOs dados não foram alterados; a operação será simplesmente interrompida.","t_speed":"Velocidade: {0}/s","t_remaining":"Restante estimado: {0}","wipe_started_log":"Limpeza segura iniciada para o disco {0}. Método: {1}","queue_log":"{0} discos na fila; serão limpos um após o outro.","queue_next_log":"Passando para o próximo disco na fila: Disco {0}...","queue_cancel_log":"Os discos restantes na fila foram ignorados devido a erro/cancelamento.","done_msg":"Concluído!\n\nTodos os dados em {0} disco(s) foram destruídos irreversivelmente de acordo com o padrão selecionado.","report_msg":"\n\nRelatório(s) salvo(s) na pasta de relatórios.","success_title":"Strix Disk Cleaner - Sucesso","speed_started_log":"Teste de velocidade iniciado: Disco {0} ({1}) - a fase de leitura é sempre segura; a fase de gravação usa um arquivo temporário quando possível.","speed_phase1":"Teste de velocidade: leitura sequencial... {0}","speed_phase2":"Teste de velocidade: leitura aleatória 4K...","speed_read_summary":"Leitura : sequencial {0}/s  |  aleatória 4K {1:N0} IOPS (méd {2:N1} ms)","speed_write_summary":"Gravação: sequencial {0}/s  |  aleatória 4K {1:N0} IOPS (méd {2:N1} ms)","speed_write_raw_summary":"Gravação: sequencial {0}/s  (modo RAW; fase de gravação aleatória ignorada)","speed_phase3":"Teste de velocidade: gravação sequencial... {0}","speed_phase4":"Teste de velocidade: gravação aleatória 4K...","speed_write_file_log":"Alvo do teste de gravação: arquivo temporário em {0}: (não destrutivo, excluído em seguida).","speed_write_raw_question":"Este disco não possui volume montado com espaço livre suficiente para um teste de gravação SEGURO.\nA velocidade de gravação só pode ser medida SOBRESCREVENDO os primeiros {0} do disco com dados de teste - tudo o que estiver armazenado nessa área será DESTRUÍDO.\n\nProsseguir com o teste de gravação RAW destrutivo?","speed_write_none":"Teste de gravação ignorado.","speed_done_log":"Teste de velocidade concluído. {0}","speed_note":"Observação: os resultados de gravação baseada em arquivo incluem a sobrecarga do sistema de arquivos, portanto podem ficar ligeiramente abaixo da velocidade RAW do dispositivo.","speed_status":"Teste de velocidade concluído. Os resultados estão no registro.","speed_msg":"Disco {0} ({1})\n\n{2}","speed_title":"Strix Disk Cleaner - Teste de Velocidade","speed_error_log":"ERRO no teste de velocidade: {0}","trace_started_log":"Varredura de vestígios de dados iniciada: Disco {0} - amostragem somente leitura.","trace_status":"Procurando vestígios de dados (lendo amostras aleatórias)...","trace_summary":"Amostras: {0} blocos  |  Contendo vestígios de dados: {1} ({2}%)  |  Zerados (em branco): {3}  |  0xFF: {4}  |  Entropia média: {5:N2} bits/byte","trace_note_empty":"O disco parece estar em grande parte em branco/zerado.","trace_note_present":"VESTÍGIOS DE DADOS RECUPERÁVEIS estão presentes - recomenda-se uma limpeza segura antes do descarte.","trace_note_encrypted":"Entropia alta: os dados podem estar criptografados/compactados; a limpeza segura ainda é recomendada.","trace_title":"Strix Disk Cleaner - Varredura de Vestígios de Dados","trace_error_log":"ERRO na varredura de vestígios de dados: {0}","surface_question":"O teste de superfície lê o disco INTEIRO; para {0} isso pode levar muito tempo, dependendo da velocidade do disco.\nOs dados não são alterados. Iniciar?","surface_title":"Teste de Superfície","surface_started_log":"Teste de superfície iniciado: Disco {0} ({1}) - toda a superfície será varrida somente para leitura.","surface_ok_msg":"Teste de superfície concluído.\n\nNenhum bloco ilegível foi encontrado - a superfície parece saudável.","surface_bad_msg":"Teste de superfície concluído.\n\nAVISO: {0} blocos ilegíveis de 64 KB foram encontrados!\nPrimeiras localizações (deslocamentos em bytes):\n{1}\n\nEste disco não é adequado para armazenamento confiável.","pdf_ok_log":"Certificado PDF criado: {0}","pdf_html_log":"Conversor de PDF (Edge) não encontrado; certificado HTML salvo: {0} (abra-o em um navegador e imprima em PDF com Ctrl+P).","pdf_error_log":"Não foi possível criar o certificado PDF: {0}","theme_dil_question":"O aplicativo será reiniciado para aplicar esta alteração. Continuar?","theme_dil_title":"Reinicialização Necessária","busy_msg":"Esta configuração não pode ser alterada enquanto uma operação está em andamento.","temp_fmt":"Temperatura: {0} C (pico: {1} C)","temp_report":"Temp Durante a Limpeza  : pico de {0} C medido","uefi_question":"O computador será reiniciado diretamente nas configurações UEFI/BIOS em 5 segundos.\nVocê salvou seus arquivos abertos? (Funciona apenas em sistemas UEFI.)","uefi_title":"Reiniciar nas Configurações UEFI/BIOS","health_panel":"INTEGRIDADE / SMART:","m_op_started":"Operação iniciada: Disco {0} ({1}), {2} GB","m_method":"Método: {0}","m_protect_ok":"Escudo de proteção: identidade do disco de destino verificada - NÃO é o disco do sistema, não contém {0}.","m_status_partition":"Limpando a tabela de partições...","m_cleardisk_note":"Observação: aviso do Clear-Disk ({0}) - continuando.","m_raw_error":"Não foi possível abrir o acesso RAW ao disco (erro Win32: {0}). Feche os programas que estão usando o disco e tente novamente.","m_status_write":"Gravando no disco...","m_pass_fmt":"Passagem {0} / {1}  ({2})","m_pass_start":"Passagem {0}/{1} iniciada (padrão: {2}).","m_pass_done":"Passagem {0}/{1} concluída.","m_random":"aleatório","m_status_verify":"Verificando (relendo o disco)...","m_verification_label":"Verificação","m_dv_fail":"FALHA NA VERIFICAÇÃO: padrão esperado não encontrado em {0} blocos amostrados!","m_dv_ok_pattern":"APROVADO ({0} pontos de amostra verificados em relação ao padrão)","m_dv_ok_rand":"APROVADO ({0} pontos de amostra relidos; a última passagem foi aleatória, portanto não se aplica comparação de padrão)","m_dv_log":"Verificação: {0}","m_notdone":"Não realizada","m_status_format":"Preparando o disco novamente (partição + formatação)...","m_format_log":"Criando uma nova partição e realizando formatação rápida...","m_disk_ready":"Disco pronto: formatado como unidade {0}: ({1}).","m_status_trim":"Enviando TRIM (notificando a controladora sobre blocos livres)...","m_trim_start":"SSD detectado: executando Optimize-Volume -ReTrim...","m_trim_ok":"TRIM concluído: a controladora foi instruída a liberar também os blocos obsoletos em sua tabela de mapeamento.","m_trim_error":"Etapa de TRIM ignorada: {0}","m_trim_none_partition":"Observação: o TRIM precisa de um volume; o ReTrim não foi aplicado porque a opção de preparar o disco está desativada.","m_format_skipped":"Formatação ignorada: {0} (Você pode inicializar o disco manualmente no Gerenciamento de Disco.)","m_report_saved":"Relatório de destruição salvo: {0}","m_status_done":"CONCLUÍDO - Os dados foram destruídos irreversivelmente.","m_op_ok":"Operação concluída com sucesso.","m_cancel":"Operação cancelada pelo usuário. AVISO: o disco pode estar parcialmente limpo; os dados estão inconsistentes.","m_cancel_read":"Varredura cancelada pelo usuário (os dados não foram alterados).","m_error":"ERRO: {0}","m_k_boot":"PROTEÇÃO ({0}): O disco de destino parece atualmente ser o disco de BOOT - operação interrompida!","m_k_system":"PROTEÇÃO ({0}): O disco de destino contém a partição SYSTEM/EFI - operação interrompida!","m_k_serial_match":"PROTEÇÃO ({0}): O número de série do disco de destino corresponde ao disco de sistema protegido - operação interrompida!","m_k_num":"PROTEÇÃO ({0}): O número do disco de destino está na lista protegida - operação interrompida!","m_k_serial_changed":"PROTEÇÃO ({0}): A identidade do disco MUDOU! Número de série confirmado {1}, encontrado {2}. Os dispositivos podem ter sido renumerados - interrompido por segurança.","m_k_size":"PROTEÇÃO ({0}): O tamanho do disco não corresponde ao confirmado (esperado {1}, encontrado {2}) - operação interrompida.","m_k_c":"PROTEÇÃO ({0}): O disco de destino hospeda a unidade {1} - operação interrompida!","m_y_status":"Varrendo a superfície (somente leitura)...","m_y_error":"Região ilegível: começando no deslocamento {0}, {1} sub-blocos de 64 KB com falha.","m_y_ok":"Teste de superfície concluído: nenhum bloco ilegível encontrado.","m_y_done":"Teste de superfície concluído: {0} blocos ilegíveis de 64 KB.","m_trim_applied":"Aplicado - blocos livres reportados à controladora","m_trim_notapplied":"Não aplicado","r_template":"=====================================================================\n                RELATÓRIO / CERTIFICADO DE DESTRUIÇÃO DE DADOS\n=====================================================================\nCriado Por        : Strix Disk Cleaner v2.3\nData do Relatório : {0}\nComputador        : {1}  (Usuário: {2})\n\n--- MÍDIA DESTRUÍDA ---\nNúmero do Disco   : {3}\nModelo            : {4}\nNúmero de Série   : {5}\nCapacidade        : {6} GB ({7} bytes)\nTipo de Mídia     : {8}  |  Barramento: {9}\nDetectado         : {10}\nIntegridade Prévia: {11}\n\n--- MÉTODO APLICADO ---\nPadrão / Método   : {12}\nNº de Passagens   : {13}\nTotal Gravado     : {14} GB\nVerificação       : {15}\nTRIM (ReTrim)     : {16}\nDuração           : {17} min {18} s\nResultado         : SUCESSO - todos os setores da mídia foram sobrescritos.\n\nOBSERVAÇÃO (NIST SP 800-88 Rev.1): A sobrescrita fornece o nível Clear.\nPara o nível Purge em mídias SSD/NVMe, etapa adicional:\n{19}\n=====================================================================","s_healthy":"Saudável","s_warning":"AVISO","s_unhealthy":"COM PROBLEMAS","s_wear":"Desgaste: {0}% (vida útil restante estimada ~{1}%)","s_wear_none":"Dados de desgaste não reportados","s_hours":"Ligado: {0:N0} horas (~{1:N0} dias)","s_temp":"Temperatura: {0} C","s_temp_max":" (máxima registrada: {0} C)","s_errors":"Erros: leitura {0} (incorrigíveis: {1}), gravação {2} (incorrigíveis: {3})","s_smart":"Previsão de falha SMART: {0}","s_smart_bad":"FALHA PREVISTA - FAÇA BACKUP AGORA!","s_smart_good":"Normal (nenhuma falha prevista)","s_counter_none":"Os contadores de confiabilidade não são expostos para este disco/barramento.","s_query_none":"A consulta de integridade falhou (gabinetes/pontes USB geralmente não repassam dados SMART).","cert_title":"CERTIFICADO DE DESTRUIÇÃO DE DADOS","cert_sub":"Destruição segura de dados em conformidade com NIST SP 800-88 Rev.1","cert_verification":"Código de Verificação (SHA-256 do relatório)","cert_field_disk":"Disco","cert_field_serial":"Nº de Série","cert_field_capacity":"Capacidade","cert_field_method":"Método","cert_field_pass":"Passagens","cert_field_dv":"Verificação","cert_field_duration":"Duração","cert_field_date":"Data","cert_field_pc":"Computador","cert_field_health":"Integridade Prévia","cert_field_result":"Resultado","cert_field_temp":"Temperatura de Pico","cert_result":"SUCESSO - todos os setores sobrescritos","lbl_report_folder":"Pasta de relatórios:","btn_report_folder":"Alterar...","report_folder_title":"Escolha onde os relatórios/certificados são salvos","chk_eject":"Ejetar discos USB com segurança ao terminar","chk_task":"Mostrar o progresso da limpeza no ícone da barra de tarefas","hpa_none":"Sem área oculta (HPA/DCO): toda a capacidade física é endereçável.","hpa_present":"ÁREA OCULTA DETECTADA (HPA/DCO): {0} deste disco ({1} setores) está oculto do sistema operacional e NÃO será sobrescrito. Para uma destruição completa, use a ferramenta do fabricante ou um Secure Erase por hardware (consulte o README).","hpa_query_none":"A verificação de área oculta (HPA/DCO) não está disponível neste barramento (pontes USB geralmente bloqueiam comandos ATA).","preview_title":"Conteúdo do disco (visualização somente leitura)","preview_empty":"Nenhum volume / partição montado detectado neste disco.","preview_partition":"  {0}: {1}  |  {2} de {3} usados ({4}% cheio)  |  {5}","preview_partition_noletter":"  Partição {0}: {1}  (sem letra de unidade)","preview_summary":"Este disco tem {0} partição(ões), cerca de {1} de dados no total.","preview_title_panel":"CONTEÚDO:","smart_title":"Atributos SMART - Disco {0}","smart_col_name":"Atributo","smart_col_value":"Valor","smart_col_worst":"Pior","smart_col_raw":"Bruto","smart_none":"A tabela bruta de atributos SMART não está disponível para este disco (ponte USB ou NVMe - o resumo de integridade acima ainda se aplica).","smart_btn":"Detalhes SMART","smart_check":"VERIFICAR","eject_ok":"Disco USB {0} ejetado - você pode desconectá-lo com segurança agora.","eject_error":"A ejeção automática falhou ({0}); use o ícone \"Remover Hardware com Segurança\" na bandeja.","trace_note_clean":"O disco está essencialmente em branco - apenas estruturas de partição foram encontradas (nenhum dado de usuário recuperável).","lbl_language":"Idioma:","already_running":"O Strix Disk Cleaner já está em execução."},
"pl":{"window_title":"Strix Disk Cleaner v2.3 - Profesjonalne narzędzie do niszczenia danych","sub_title":"Nieodwracalne wymazywanie dysków zgodne z NIST SP 800-88 i DoD 5220.22-M","lbl_theme":"Motyw:","theme_dark":"Ciemny","theme_light":"Jasny","col_disk":"Dysk","col_type":"Typ","col_bus":"Magistrala","col_size":"Rozmiar","col_serial":"Nr seryjny","col_health":"Stan","col_life":"Żywotność","col_hours":"Godziny","col_temp":"Temp.","btn_uefi":"Uruchom ponownie do ustawień UEFI/BIOS","lbl_method":"Metoda wymazywania:","y0":"NIST SP 800-88 Clear  -  Pojedynczy przebieg 0x00 (ZALECANE, wystarczające dla nowoczesnych dysków)","y1":"Pojedynczy przebieg kryptograficznych danych losowych","y2":"DoD 5220.22-M  -  3 przebiegi (0x00 / 0xFF / losowe) + weryfikacja","y3":"Zaawansowana  -  7 przebiegów (podobna do VSITR, bardzo wolna)","chk_verify":"Weryfikuj po wymazaniu (odczytaj ponownie z dysku i sprawdź)","chk_format":"Przygotuj dysk do użytku po zakończeniu (utwórz partycję + szybkie formatowanie)","chk_report":"Zapisz raport z niszczenia danych (certyfikat) w folderze raportów","chk_pdf":"Utwórz również certyfikat PDF (z kodem weryfikacyjnym; działa z opcją raportu)","chk_sound":"Odtwórz dźwięk i mignij oknem po zakończeniu","btn_refresh":"Odśwież listę","btn_speed":"Test szybkości","btn_trace":"Skanowanie śladów danych","btn_surface":"Test powierzchni","btn_wipe":"BEZPIECZNE WYMAZANIE","btn_cancel":"Anuluj","status_ready":"Gotowe. Wybierz dysk(i) do wymazania (przytrzymaj Ctrl, aby zaznaczyć wiele).","confirm_title":"Potwierdź, wpisując","confirm_text":"Ze względów bezpieczeństwa wpisz ERASE wielkimi literami w polu poniżej, aby kontynuować:","btn_back":"Wstecz","btn_startwipe":"ROZPOCZNIJ WYMAZYWANIE","ready_log":"Strix Disk Cleaner v2.3 gotowy. Możliwości sprzętowe i dane o stanie (SMART) są odpytywane automatycznie po wybraniu dysku.","protect_log":"TARCZA OCHRONNA AKTYWNA: dysk zawierający {0} oraz wszystkie dyski rozruchowe/systemowe nigdy nie mogą zostać wybrane; kontrole tożsamości są powtarzane podczas wymazywania.","first_disk_select":"Najpierw wybierz dysk z listy.","protect_block_log":"TARCZA OCHRONNA ZABLOKOWAŁA: {0}","protect_block_msg":"TARCZA OCHRONNA zadziałała:\n\n{0}\n\nTen dysk nigdy nie może zostać wymazany.","protect_block_title":"Strix Disk Cleaner - Ochrona dysku systemowego","summary_start":"WSZYSTKIE DANE NA PONIŻSZYCH {0} DYSKU(-ACH) ZOSTANĄ TRWALE ZNISZCZONE:","summary_disk":"  Dysk {0}: {1}  |  {2}  |  {3} ({4})  |  Nr seryjny: {5}","summary_method":"Metoda: {0}","summary_final":"Tej operacji NIE MOŻNA cofnąć. Kontynuować?","final_warning_title":"OSTATNIE OSTRZEŻENIE","confirm_none_log":"Operacja anulowana przez użytkownika (nie udzielono potwierdzenia).","cancel_question":"Czy na pewno chcesz anulować?\nDysk pozostanie częściowo wymazany (niespójny).","cancel_title":"Potwierdzenie anulowania","cancel_question_read":"Czy na pewno chcesz anulować operację testu powierzchni/skanowania?\nDane nie zostały naruszone; operacja zostanie po prostu przerwana.","t_speed":"Szybkość: {0}/s","t_remaining":"Szac. pozostało: {0}","wipe_started_log":"Rozpoczęto bezpieczne wymazywanie dysku {0}. Metoda: {1}","queue_log":"Dodano {0} dysków do kolejki; zostaną wymazane jeden po drugim.","queue_next_log":"Przechodzenie do następnego dysku w kolejce: Dysk {0}...","queue_cancel_log":"Pozostałe dyski w kolejce zostały pominięte z powodu błędu/anulowania.","done_msg":"Gotowe!\n\nWszystkie dane na {0} dysku(-ach) zostały nieodwracalnie zniszczone zgodnie z wybranym standardem.","report_msg":"\n\nRaport(y) zapisano w folderze raportów.","success_title":"Strix Disk Cleaner - Sukces","speed_started_log":"Rozpoczęto test szybkości: Dysk {0} ({1}) - faza odczytu jest zawsze bezpieczna; faza zapisu w miarę możliwości używa pliku tymczasowego.","speed_phase1":"Test szybkości: odczyt sekwencyjny... {0}","speed_phase2":"Test szybkości: losowy odczyt 4K...","speed_read_summary":"Odczyt : sekwencyjny {0}/s  |  losowy 4K {1:N0} IOPS (śr. {2:N1} ms)","speed_write_summary":"Zapis: sekwencyjny {0}/s  |  losowy 4K {1:N0} IOPS (śr. {2:N1} ms)","speed_write_raw_summary":"Zapis: sekwencyjny {0}/s  (tryb surowy; faza zapisu losowego pominięta)","speed_phase3":"Test szybkości: zapis sekwencyjny... {0}","speed_phase4":"Test szybkości: losowy zapis 4K...","speed_write_file_log":"Cel testu zapisu: plik tymczasowy na {0}: (nieniszczący, usuwany po zakończeniu).","speed_write_raw_question":"Ten dysk nie ma zamontowanego woluminu z wystarczającą ilością wolnego miejsca na BEZPIECZNY test zapisu.\nSzybkość zapisu można zmierzyć tylko przez NADPISANIE pierwszych {0} dysku danymi testowymi - wszystko, co jest przechowywane w tym obszarze, zostanie ZNISZCZONE.\n\nKontynuować niszczący, surowy test zapisu?","speed_write_none":"Test zapisu pominięty.","speed_done_log":"Test szybkości zakończony. {0}","speed_note":"Uwaga: wyniki zapisu oparte na pliku uwzględniają narzut systemu plików, więc mogą być nieco niższe od surowej szybkości urządzenia.","speed_status":"Test szybkości zakończony. Wyniki znajdują się w dzienniku.","speed_msg":"Dysk {0} ({1})\n\n{2}","speed_title":"Strix Disk Cleaner - Test szybkości","speed_error_log":"BŁĄD testu szybkości: {0}","trace_started_log":"Rozpoczęto skanowanie śladów danych: Dysk {0} - próbkowanie tylko do odczytu.","trace_status":"Skanowanie w poszukiwaniu śladów danych (odczyt losowych próbek)...","trace_summary":"Próbki: {0} bloków  |  Zawierające ślady danych: {1} ({2}%)  |  Wyzerowane (puste): {3}  |  0xFF: {4}  |  Śr. entropia: {5:N2} bitów/bajt","trace_note_empty":"Dysk wydaje się w większości pusty/wyzerowany.","trace_note_present":"Obecne są MOŻLIWE DO ODZYSKANIA ŚLADY DANYCH - przed utylizacją zaleca się bezpieczne wymazanie.","trace_note_encrypted":"Wysoka entropia: dane mogą być zaszyfrowane/skompresowane; bezpieczne wymazanie jest nadal zalecane.","trace_title":"Strix Disk Cleaner - Skanowanie śladów danych","trace_error_log":"BŁĄD skanowania śladów danych: {0}","surface_question":"Test powierzchni odczytuje CAŁY dysk; dla {0} może to zająć dużo czasu, w zależności od szybkości dysku.\nDane nie zostaną naruszone. Rozpocząć?","surface_title":"Test powierzchni","surface_started_log":"Rozpoczęto test powierzchni: Dysk {0} ({1}) - cała powierzchnia zostanie zeskanowana tylko do odczytu.","surface_ok_msg":"Test powierzchni zakończony.\n\nNie znaleziono nieczytelnych bloków - powierzchnia wygląda na sprawną.","surface_bad_msg":"Test powierzchni zakończony.\n\nOSTRZEŻENIE: znaleziono {0} nieczytelnych bloków 64 KB!\nPierwsze lokalizacje (przesunięcia bajtowe):\n{1}\n\nTen dysk nie nadaje się do niezawodnego przechowywania danych.","pdf_ok_log":"Utworzono certyfikat PDF: {0}","pdf_html_log":"Nie znaleziono konwertera PDF (Edge); zapisano certyfikat HTML: {0} (otwórz go w przeglądarce i wydrukuj do PDF za pomocą Ctrl+P).","pdf_error_log":"Nie można utworzyć certyfikatu PDF: {0}","theme_dil_question":"Aplikacja zostanie uruchomiona ponownie, aby zastosować tę zmianę. Kontynuować?","theme_dil_title":"Wymagane ponowne uruchomienie","busy_msg":"Tego ustawienia nie można zmienić, gdy trwa operacja.","temp_fmt":"Temperatura: {0} C (szczytowa: {1} C)","temp_report":"Temp. podczas wymazywania  : zmierzona szczytowa {0} C","uefi_question":"Komputer uruchomi się ponownie bezpośrednio do ustawień UEFI/BIOS za 5 sekund.\nCzy zapisałeś otwarte pliki? (Działa tylko w systemach UEFI.)","uefi_title":"Uruchom ponownie do UEFI/BIOS","health_panel":"STAN / SMART:","m_op_started":"Rozpoczęto operację: Dysk {0} ({1}), {2} GB","m_method":"Metoda: {0}","m_protect_ok":"Tarcza ochronna: zweryfikowano tożsamość dysku docelowego - NIE jest dyskiem systemowym, nie zawiera {0}.","m_status_partition":"Czyszczenie tablicy partycji...","m_cleardisk_note":"Uwaga: ostrzeżenie Clear-Disk ({0}) - kontynuowanie.","m_raw_error":"Nie można otworzyć surowego dostępu do dysku (błąd Win32: {0}). Zamknij programy używające dysku i spróbuj ponownie.","m_status_write":"Zapisywanie na dysk...","m_pass_fmt":"Przebieg {0} / {1}  ({2})","m_pass_start":"Rozpoczęto przebieg {0}/{1} (wzorzec: {2}).","m_pass_done":"Zakończono przebieg {0}/{1}.","m_random":"losowy","m_status_verify":"Weryfikowanie (ponowny odczyt z dysku)...","m_verification_label":"Weryfikacja","m_dv_fail":"WERYFIKACJA NIEUDANA: nie znaleziono oczekiwanego wzorca w {0} próbkowanych blokach!","m_dv_ok_pattern":"ZALICZONO ({0} punktów próbnych zweryfikowanych względem wzorca)","m_dv_ok_rand":"ZALICZONO ({0} punktów próbnych odczytanych ponownie; ostatni przebieg był losowy, więc porównanie wzorca nie ma zastosowania)","m_dv_log":"Weryfikacja: {0}","m_notdone":"Nie wykonano","m_status_format":"Ponowne przygotowywanie dysku (partycja + formatowanie)...","m_format_log":"Tworzenie nowej partycji i szybkie formatowanie...","m_disk_ready":"Dysk gotowy: sformatowany jako napęd {0}: ({1}).","m_status_trim":"Wysyłanie TRIM (powiadamianie kontrolera o wolnych blokach)...","m_trim_start":"Wykryto SSD: uruchamianie Optimize-Volume -ReTrim...","m_trim_ok":"TRIM zakończony: kontroler otrzymał również polecenie zwolnienia nieaktualnych bloków w swojej tablicy mapowania.","m_trim_error":"Krok TRIM pominięty: {0}","m_trim_none_partition":"Uwaga: TRIM wymaga woluminu; ReTrim nie został zastosowany, ponieważ opcja przygotowania dysku jest wyłączona.","m_format_skipped":"Formatowanie pominięte: {0} (Dysk można zainicjować ręcznie w Zarządzaniu dyskami.)","m_report_saved":"Zapisano raport z niszczenia: {0}","m_status_done":"ZAKOŃCZONO - Dane zostały nieodwracalnie zniszczone.","m_op_ok":"Operacja zakończona pomyślnie.","m_cancel":"Operacja anulowana przez użytkownika. OSTRZEŻENIE: dysk może być częściowo wymazany; dane są niespójne.","m_cancel_read":"Skanowanie anulowane przez użytkownika (dane nie zostały naruszone).","m_error":"BŁĄD: {0}","m_k_boot":"OCHRONA ({0}): Dysk docelowy wydaje się obecnie być dyskiem ROZRUCHOWYM - operacja zatrzymana!","m_k_system":"OCHRONA ({0}): Dysk docelowy zawiera partycję SYSTEM/EFI - operacja zatrzymana!","m_k_serial_match":"OCHRONA ({0}): Numer seryjny dysku docelowego pasuje do chronionego dysku systemowego - operacja zatrzymana!","m_k_num":"OCHRONA ({0}): Numer dysku docelowego znajduje się na liście chronionych - operacja zatrzymana!","m_k_serial_changed":"OCHRONA ({0}): Tożsamość dysku ZMIENIŁA się! Potwierdzony numer seryjny {1}, znaleziono {2}. Urządzenia mogły zostać przenumerowane - zatrzymano ze względów bezpieczeństwa.","m_k_size":"OCHRONA ({0}): Rozmiar dysku nie pasuje do potwierdzonego (oczekiwano {1}, znaleziono {2}) - operacja zatrzymana.","m_k_c":"OCHRONA ({0}): Dysk docelowy zawiera napęd {1} - operacja zatrzymana!","m_y_status":"Skanowanie powierzchni (tylko do odczytu)...","m_y_error":"Nieczytelny obszar: początek na przesunięciu {0}, {1} uszkodzonych podbloków 64 KB.","m_y_ok":"Test powierzchni zakończony: nie znaleziono nieczytelnych bloków.","m_y_done":"Test powierzchni zakończony: {0} nieczytelnych bloków 64 KB.","m_trim_applied":"Zastosowano - wolne bloki zgłoszono do kontrolera","m_trim_notapplied":"Nie zastosowano","r_template":"=====================================================================\n                RAPORT / CERTYFIKAT NISZCZENIA DANYCH\n=====================================================================\nUtworzono przez   : Strix Disk Cleaner v2.3\nData raportu      : {0}\nKomputer          : {1}  (Użytkownik: {2})\n\n--- ZNISZCZONY NOŚNIK ---\nNumer dysku       : {3}\nModel             : {4}\nNumer seryjny     : {5}\nPojemność         : {6} GB ({7} bajtów)\nTyp nośnika       : {8}  |  Magistrala: {9}\nWykryto           : {10}\nStan przed wymaz. : {11}\n\n--- ZASTOSOWANA METODA ---\nStandard / Metoda : {12}\nLiczba przebiegów : {13}\nŁącznie zapisano  : {14} GB\nWeryfikacja       : {15}\nTRIM (ReTrim)     : {16}\nCzas trwania      : {17} min {18} s\nWynik             : SUKCES - każdy sektor nośnika został nadpisany.\n\nUWAGA (NIST SP 800-88 Rev.1): Nadpisywanie zapewnia poziom Clear.\nDla poziomu Purge na nośnikach SSD/NVMe, dodatkowy krok:\n{19}\n=====================================================================","s_healthy":"Sprawny","s_warning":"OSTRZEŻENIE","s_unhealthy":"NIESPRAWNY","s_wear":"Zużycie: {0}% (szacowana pozostała żywotność ~{1}%)","s_wear_none":"Brak danych o zużyciu","s_hours":"Czas pracy: {0:N0} godzin (~{1:N0} dni)","s_temp":"Temperatura: {0} C","s_temp_max":" (najwyższa odnotowana: {0} C)","s_errors":"Błędy: odczyt {0} (niekorygowalne: {1}), zapis {2} (niekorygowalne: {3})","s_smart":"Prognoza awarii SMART: {0}","s_smart_bad":"PRZEWIDYWANA AWARIA - WYKONAJ KOPIĘ ZAPASOWĄ TERAZ!","s_smart_good":"Normalny (brak przewidywanej awarii)","s_counter_none":"Liczniki niezawodności nie są udostępniane dla tego dysku/magistrali.","s_query_none":"Zapytanie o stan nie powiodło się (obudowy/mostki USB zwykle nie przekazują danych SMART).","cert_title":"CERTYFIKAT NISZCZENIA DANYCH","cert_sub":"Bezpieczne niszczenie danych zgodne z NIST SP 800-88 Rev.1","cert_verification":"Kod weryfikacyjny (SHA-256 raportu)","cert_field_disk":"Dysk","cert_field_serial":"Nr seryjny","cert_field_capacity":"Pojemność","cert_field_method":"Metoda","cert_field_pass":"Przebiegi","cert_field_dv":"Weryfikacja","cert_field_duration":"Czas trwania","cert_field_date":"Data","cert_field_pc":"Komputer","cert_field_health":"Stan przed wymazaniem","cert_field_result":"Wynik","cert_field_temp":"Temperatura szczytowa","cert_result":"SUKCES - wszystkie sektory nadpisane","lbl_report_folder":"Folder raportów:","btn_report_folder":"Zmień...","report_folder_title":"Wybierz miejsce zapisu raportów/certyfikatów","chk_eject":"Bezpiecznie wysuń dyski USB po zakończeniu","chk_task":"Pokaż postęp wymazywania na ikonie paska zadań","hpa_none":"Brak ukrytego obszaru (HPA/DCO): cała pojemność fizyczna jest adresowalna.","hpa_present":"WYKRYTO UKRYTY OBSZAR (HPA/DCO): {0} tego dysku ({1} sektorów) jest ukryte przed systemem operacyjnym i NIE zostanie nadpisane. W celu pełnego zniszczenia użyj narzędzia producenta lub sprzętowego Secure Erase (zobacz README).","hpa_query_none":"Kontrola ukrytego obszaru (HPA/DCO) niedostępna na tej magistrali (mostki USB zwykle blokują polecenia ATA).","preview_title":"Zawartość dysku (podgląd tylko do odczytu)","preview_empty":"Nie wykryto zamontowanych woluminów / partycji na tym dysku.","preview_partition":"  {0}: {1}  |  wykorzystano {2} z {3} ({4}% zapełnienia)  |  {5}","preview_partition_noletter":"  Partycja {0}: {1}  (brak litery napędu)","preview_summary":"Ten dysk ma {0} partycję(-e), łącznie około {1} danych.","preview_title_panel":"ZAWARTOŚĆ:","smart_title":"Atrybuty SMART - Dysk {0}","smart_col_name":"Atrybut","smart_col_value":"Wartość","smart_col_worst":"Najgorsza","smart_col_raw":"Surowa","smart_none":"Surowa tablica atrybutów SMART nie jest dostępna dla tego dysku (mostek USB lub NVMe - powyższe podsumowanie stanu nadal obowiązuje).","smart_btn":"Szczegóły SMART","smart_check":"SPRAWDŹ","eject_ok":"Dysk USB {0} wysunięty - możesz go teraz bezpiecznie odłączyć.","eject_error":"Automatyczne wysuwanie nie powiodło się ({0}); użyj ikony \"Bezpieczne usuwanie sprzętu\" w zasobniku systemowym.","trace_note_clean":"Dysk jest zasadniczo pusty - znaleziono tylko struktury partycji (brak możliwych do odzyskania danych użytkownika).","lbl_language":"Język:","already_running":"Strix Disk Cleaner jest już uruchomiony."},
"uk":{"window_title":"Strix Disk Cleaner v2.3 - Професійний інструмент для знищення даних","sub_title":"Незворотне очищення дисків відповідно до NIST SP 800-88 та DoD 5220.22-M","lbl_theme":"Тема:","theme_dark":"Темна","theme_light":"Світла","col_disk":"Диск","col_model":"Модель","col_type":"Тип","col_bus":"Шина","col_size":"Розмір","col_serial":"Серійний №","col_health":"Стан","col_life":"Ресурс","col_hours":"Години","col_temp":"Темп.","btn_uefi":"Перезавантажити в налаштування UEFI/BIOS","lbl_method":"Метод очищення:","y0":"NIST SP 800-88 Clear  -  Один прохід 0x00 (РЕКОМЕНДОВАНО, достатньо для сучасних дисків)","y1":"Один прохід криптографічно випадкових даних","y2":"DoD 5220.22-M  -  3 проходи (0x00 / 0xFF / випадкові) + перевірка","y3":"Розширений  -  7 проходів (подібно до VSITR, дуже повільно)","chk_verify":"Перевіряти після очищення (зчитати з диска та звірити)","chk_format":"Зробити диск придатним до використання після завершення (створити розділ + швидке форматування)","chk_report":"Зберегти звіт про знищення даних (сертифікат) у папку звітів","chk_pdf":"Також створити PDF-сертифікат (з кодом перевірки; працює з опцією звіту)","chk_sound":"Відтворити звук і блимнути вікном після завершення","btn_refresh":"Оновити список","btn_speed":"Тест швидкості","btn_trace":"Сканування слідів даних","btn_surface":"Тест поверхні","btn_wipe":"БЕЗПЕЧНЕ СТИРАННЯ","btn_cancel":"Скасувати","status_ready":"Готово. Виберіть диск(и) для очищення (утримуйте Ctrl, щоб вибрати кілька).","confirm_title":"Підтвердьте введенням","confirm_text":"Задля безпеки введіть ERASE великими літерами в поле нижче, щоб продовжити:","btn_back":"Назад","btn_startwipe":"ПОЧАТИ ОЧИЩЕННЯ","ready_log":"Strix Disk Cleaner v2.3 готовий. Апаратні можливості та дані про стан (SMART) запитуються автоматично, коли ви вибираєте диск.","protect_log":"ЗАХИСНИЙ ЩИТ АКТИВНИЙ: диск, що містить {0}, та всі завантажувальні/системні диски ніколи не можуть бути обрані; перевірки ідентичності повторюються під час очищення.","first_disk_select":"Спочатку виберіть диск зі списку.","protect_block_log":"ЗАХИСНИЙ ЩИТ ЗАБЛОКУВАВ: {0}","protect_block_msg":"ЗАХИСНИЙ ЩИТ задіяно:\n\n{0}\n\nЦей диск ніколи не може бути очищено.","protect_block_title":"Strix Disk Cleaner - Захист системного диска","summary_start":"ВСІ ДАНІ НА НАСТУПНИХ {0} ДИСКАХ БУДУТЬ ЗНИЩЕНІ НАЗАВЖДИ:","summary_disk":"  Диск {0}: {1}  |  {2}  |  {3} ({4})  |  Серійний №: {5}","summary_method":"Метод: {0}","summary_final":"Це НЕМОЖЛИВО скасувати. Продовжити?","final_warning_title":"ОСТАННЄ ПОПЕРЕДЖЕННЯ","confirm_none_log":"Операцію скасовано користувачем (підтвердження не надано).","cancel_question":"Ви впевнені, що хочете скасувати?\nДиск залишиться частково очищеним (у неузгодженому стані).","cancel_title":"Підтвердження скасування","cancel_question_read":"Ви впевнені, що хочете скасувати операцію тесту поверхні/сканування?\nДані не змінювалися; операцію буде просто перервано.","t_speed":"Швидкість: {0}/с","t_remaining":"Залишилось (прибл.): {0}","wipe_started_log":"Розпочато безпечне очищення диска {0}. Метод: {1}","queue_log":"{0} дисків додано в чергу; вони будуть очищені один за одним.","queue_next_log":"Перехід до наступного диска в черзі: Диск {0}...","queue_cancel_log":"Решту дисків у черзі пропущено через помилку/скасування.","done_msg":"Готово!\n\nВсі дані на {0} дисках було незворотно знищено відповідно до обраного стандарту.","report_msg":"\n\nЗвіт(и) збережено в папку звітів.","success_title":"Strix Disk Cleaner - Успіх","speed_started_log":"Розпочато тест швидкості: Диск {0} ({1}) - фаза читання завжди безпечна; фаза запису використовує тимчасовий файл, коли це можливо.","speed_phase1":"Тест швидкості: послідовне читання... {0}","speed_phase2":"Тест швидкості: випадкове читання 4K...","speed_read_summary":"Читання: послідовне {0}/с  |  випадкове 4K {1:N0} IOPS (сер. {2:N1} мс)","speed_write_summary":"Запис: послідовний {0}/с  |  випадковий 4K {1:N0} IOPS (сер. {2:N1} мс)","speed_write_raw_summary":"Запис: послідовний {0}/с  (сирий режим; фазу випадкового запису пропущено)","speed_phase3":"Тест швидкості: послідовний запис... {0}","speed_phase4":"Тест швидкості: випадковий запис 4K...","speed_write_file_log":"Ціль тесту запису: тимчасовий файл на {0}: (без руйнування, видаляється згодом).","speed_write_raw_question":"На цьому диску немає змонтованого тому з достатнім вільним місцем для БЕЗПЕЧНОГО тесту запису.\nШвидкість запису можна виміряти лише ПЕРЕЗАПИСАВШИ перші {0} диска тестовими даними - усе, що зберігається в цій області, буде ЗНИЩЕНО.\n\nПродовжити руйнівний тест сирого запису?","speed_write_none":"Тест запису пропущено.","speed_done_log":"Тест швидкості завершено. {0}","speed_note":"Примітка: результати запису на основі файлів включають накладні витрати файлової системи, тому вони можуть бути дещо нижчими за швидкість сирого пристрою.","speed_status":"Тест швидкості завершено. Результати в журналі.","speed_msg":"Диск {0} ({1})\n\n{2}","speed_title":"Strix Disk Cleaner - Тест швидкості","speed_error_log":"ПОМИЛКА тесту швидкості: {0}","trace_started_log":"Розпочато сканування слідів даних: Диск {0} - вибіркове зчитування лише для читання.","trace_status":"Сканування слідів даних (зчитування випадкових зразків)...","trace_summary":"Зразки: {0} блоків  |  Містять сліди даних: {1} ({2}%)  |  Обнулені (порожні): {3}  |  0xFF: {4}  |  Сер. ентропія: {5:N2} біт/байт","trace_note_empty":"Диск переважно порожній/обнулений.","trace_note_present":"Присутні ВІДНОВЛЮВАНІ СЛІДИ ДАНИХ - перед утилізацією рекомендується безпечне очищення.","trace_note_encrypted":"Висока ентропія: дані можуть бути зашифровані/стиснуті; безпечне очищення все одно рекомендується.","trace_title":"Strix Disk Cleaner - Сканування слідів даних","trace_error_log":"ПОМИЛКА сканування слідів даних: {0}","surface_question":"Тест поверхні зчитує ВЕСЬ диск; для {0} це може зайняти багато часу залежно від швидкості диска.\nДані не змінюються. Розпочати?","surface_title":"Тест поверхні","surface_started_log":"Розпочато тест поверхні: Диск {0} ({1}) - вся поверхня буде просканована лише для читання.","surface_ok_msg":"Тест поверхні завершено.\n\nНечитабельних блоків не знайдено - поверхня виглядає справною.","surface_bad_msg":"Тест поверхні завершено.\n\nПОПЕРЕДЖЕННЯ: знайдено {0} нечитабельних блоків по 64 KB!\nПерші розташування (зміщення в байтах):\n{1}\n\nЦей диск непридатний для надійного зберігання.","pdf_ok_log":"PDF-сертифікат створено: {0}","pdf_html_log":"Конвертер PDF (Edge) не знайдено; збережено HTML-сертифікат: {0} (відкрийте його в браузері та роздрукуйте в PDF за допомогою Ctrl+P).","pdf_error_log":"Не вдалося створити PDF-сертифікат: {0}","theme_dil_question":"Програма перезапуститься, щоб застосувати цю зміну. Продовжити?","theme_dil_title":"Потрібен перезапуск","busy_msg":"Цей параметр не можна змінити під час виконання операції.","temp_fmt":"Температура: {0} C (пік: {1} C)","temp_report":"Темп. під час очищення  : виміряно пік {0} C","uefi_question":"Комп\u0027ютер перезавантажиться безпосередньо в налаштування UEFI/BIOS через 5 секунд.\nЧи зберегли ви відкриті файли? (Працює лише на системах UEFI.)","uefi_title":"Перезавантажити в UEFI/BIOS","health_panel":"СТАН / SMART:","m_op_started":"Розпочато операцію: Диск {0} ({1}), {2} GB","m_method":"Метод: {0}","m_protect_ok":"Захисний щит: ідентичність цільового диска перевірено - це НЕ системний диск, не містить {0}.","m_status_partition":"Очищення таблиці розділів...","m_cleardisk_note":"Примітка: попередження Clear-Disk ({0}) - продовжуємо.","m_raw_error":"Не вдалося відкрити прямий доступ до диска (помилка Win32: {0}). Закрийте програми, що використовують диск, і повторіть спробу.","m_status_write":"Запис на диск...","m_pass_fmt":"Прохід {0} / {1}  ({2})","m_pass_start":"Прохід {0}/{1} розпочато (шаблон: {2}).","m_pass_done":"Прохід {0}/{1} завершено.","m_random":"випадковий","m_status_verify":"Перевірка (зчитування з диска)...","m_verification_label":"Перевірка","m_dv_fail":"ПЕРЕВІРКУ НЕ ПРОЙДЕНО: очікуваний шаблон не знайдено у {0} перевірених блоках!","m_dv_ok_pattern":"ПРОЙДЕНО (перевірено {0} контрольних точок за шаблоном)","m_dv_ok_rand":"ПРОЙДЕНО (зчитано {0} контрольних точок; останній прохід був випадковим, тому порівняння шаблону не застосовується)","m_dv_log":"Перевірка: {0}","m_notdone":"Не виконано","m_status_format":"Повторна підготовка диска (розділ + форматування)...","m_format_log":"Створення нового розділу та швидке форматування...","m_disk_ready":"Диск готовий: відформатовано як диск {0}: ({1}).","m_status_trim":"Надсилання TRIM (сповіщення контролера про вільні блоки)...","m_trim_start":"Виявлено SSD: виконується Optimize-Volume -ReTrim...","m_trim_ok":"TRIM завершено: контролеру також наказано звільнити застарілі блоки у своїй таблиці відображення.","m_trim_error":"Крок TRIM пропущено: {0}","m_trim_none_partition":"Примітка: TRIM потребує тому; ReTrim не застосовано, оскільки опцію підготовки диска вимкнено.","m_format_skipped":"Форматування пропущено: {0} (Ви можете ініціалізувати диск вручну в Керуванні дисками.)","m_report_saved":"Звіт про знищення збережено: {0}","m_status_done":"ЗАВЕРШЕНО - Дані було незворотно знищено.","m_op_ok":"Операцію успішно завершено.","m_cancel":"Операцію скасовано користувачем. ПОПЕРЕДЖЕННЯ: диск може бути частково очищений; дані в неузгодженому стані.","m_cancel_read":"Сканування скасовано користувачем (дані не змінювалися).","m_error":"ПОМИЛКА: {0}","m_k_boot":"ЗАХИСТ ({0}): Цільовий диск наразі виявляється ЗАВАНТАЖУВАЛЬНИМ - операцію зупинено!","m_k_system":"ЗАХИСТ ({0}): Цільовий диск містить розділ SYSTEM/EFI - операцію зупинено!","m_k_serial_match":"ЗАХИСТ ({0}): Серійний номер цільового диска збігається із захищеним системним диском - операцію зупинено!","m_k_num":"ЗАХИСТ ({0}): Номер цільового диска є в захищеному списку - операцію зупинено!","m_k_serial_changed":"ЗАХИСТ ({0}): Ідентичність диска ЗМІНИЛАСЯ! Підтверджений серійний номер {1}, знайдено {2}. Пристрої могли бути перенумеровані - зупинено задля безпеки.","m_k_size":"ЗАХИСТ ({0}): Розмір диска не збігається з підтвердженим (очікувалося {1}, знайдено {2}) - операцію зупинено.","m_k_c":"ЗАХИСТ ({0}): Цільовий диск містить диск {1} - операцію зупинено!","m_y_status":"Сканування поверхні (лише для читання)...","m_y_error":"Нечитабельна область: починаючи зі зміщення {0}, {1} збійних під-блоків по 64 KB.","m_y_ok":"Тест поверхні завершено: нечитабельних блоків не знайдено.","m_y_done":"Тест поверхні завершено: {0} нечитабельних блоків по 64 KB.","m_trim_applied":"Застосовано - контролеру повідомлено про вільні блоки","m_trim_notapplied":"Не застосовано","r_template":"=====================================================================\n              ЗВІТ / СЕРТИФІКАТ ПРО ЗНИЩЕННЯ ДАНИХ\n=====================================================================\nСтворено           : Strix Disk Cleaner v2.3\nДата звіту         : {0}\nКомп\u0027ютер          : {1}  (Користувач: {2})\n\n--- ЗНИЩЕНИЙ НОСІЙ ---\nНомер диска        : {3}\nМодель             : {4}\nСерійний номер     : {5}\nЄмність            : {6} GB ({7} байт)\nТип носія          : {8}  |  Шина: {9}\nВиявлено           : {10}\nСтан до очищення   : {11}\n\n--- ЗАСТОСОВАНИЙ МЕТОД ---\nСтандарт / Метод   : {12}\nКількість проходів : {13}\nВсього записано    : {14} GB\nПеревірка          : {15}\nTRIM (ReTrim)      : {16}\nТривалість         : {17} хв {18} с\nРезультат          : УСПІХ - кожен сектор носія було перезаписано.\n\nПРИМІТКА (NIST SP 800-88 Rev.1): Перезапис забезпечує рівень Clear.\nДля рівня Purge на носіях SSD/NVMe додатковий крок:\n{19}\n=====================================================================","s_healthy":"Справний","s_warning":"ПОПЕРЕДЖЕННЯ","s_unhealthy":"НЕСПРАВНИЙ","s_status":"Статус: {0}","s_wear":"Знос: {0}% (орієнтовний залишковий ресурс ~{1}%)","s_wear_none":"Дані про знос не надано","s_hours":"Час роботи: {0:N0} годин (~{1:N0} днів)","s_temp":"Температура: {0} C","s_temp_max":" (найвище зафіксоване: {0} C)","s_errors":"Помилки: читання {0} (невиправні: {1}), запис {2} (невиправні: {3})","s_smart":"Прогноз збою SMART: {0}","s_smart_bad":"ПРОГНОЗУЄТЬСЯ ЗБІЙ - НЕГАЙНО ЗРОБІТЬ РЕЗЕРВНУ КОПІЮ!","s_smart_good":"Нормально (збою не прогнозується)","s_counter_none":"Лічильники надійності недоступні для цього диска/шини.","s_query_none":"Запит стану не вдався (USB-контейнери/мости зазвичай не передають дані SMART).","cert_title":"СЕРТИФІКАТ ПРО ЗНИЩЕННЯ ДАНИХ","cert_sub":"Безпечне знищення даних відповідно до NIST SP 800-88 Rev.1","cert_verification":"Код перевірки (SHA-256 звіту)","cert_field_disk":"Диск","cert_field_serial":"Серійний №","cert_field_capacity":"Ємність","cert_field_method":"Метод","cert_field_pass":"Проходи","cert_field_dv":"Перевірка","cert_field_duration":"Тривалість","cert_field_date":"Дата","cert_field_pc":"Комп\u0027ютер","cert_field_health":"Стан до очищення","cert_field_result":"Результат","cert_field_temp":"Пікова температура","cert_result":"УСПІХ - усі сектори перезаписано","lbl_report_folder":"Папка звітів:","btn_report_folder":"Змінити...","report_folder_title":"Виберіть, де зберігаються звіти/сертифікати","chk_eject":"Безпечно відключати USB-диски після завершення","chk_task":"Показувати перебіг очищення на значку панелі завдань","hpa_none":"Прихованої області (HPA/DCO) немає: повна фізична ємність доступна для адресації.","hpa_present":"ВИЯВЛЕНО ПРИХОВАНУ ОБЛАСТЬ (HPA/DCO): {0} цього диска ({1} секторів) приховано від ОС і НЕ буде перезаписано. Для повного знищення скористайтеся інструментом виробника або апаратним Secure Erase (див. README).","hpa_query_none":"Перевірка прихованої області (HPA/DCO) недоступна на цій шині (USB-мости зазвичай блокують команди ATA).","preview_title":"Вміст диска (перегляд лише для читання)","preview_empty":"На цьому диску не виявлено змонтованих томів / розділів.","preview_partition":"  {0}: {1}  |  використано {2} з {3} ({4}% заповнено)  |  {5}","preview_partition_noletter":"  Розділ {0}: {1}  (без літери диска)","preview_summary":"Цей диск має {0} розділ(ів), загалом близько {1} даних.","preview_title_panel":"ВМІСТ:","smart_title":"Атрибути SMART - Диск {0}","smart_col_name":"Атрибут","smart_col_value":"Значення","smart_col_worst":"Найгірше","smart_col_raw":"Необроблене","smart_col_status":"Статус","smart_none":"Таблиця необроблених атрибутів SMART недоступна для цього диска (USB-міст або NVMe - зведення про стан вище все одно застосовується).","smart_btn":"Деталі SMART","smart_check":"ПЕРЕВІРИТИ","eject_ok":"USB-диск {0} відключено - тепер ви можете безпечно від\u0027єднати його.","eject_error":"Автоматичне відключення не вдалося ({0}); скористайтеся значком \"Безпечне видалення пристрою\" в системному лотку.","trace_note_clean":"Диск фактично порожній - знайдено лише структури розділів (немає відновлюваних даних користувача).","lbl_language":"Мова:","already_running":"Strix Disk Cleaner вже запущено."},
"ru":{"window_title":"Strix Disk Cleaner v2.3 - Профессиональный инструмент уничтожения данных","sub_title":"Необратимое стирание дисков в соответствии с NIST SP 800-88 и DoD 5220.22-M","lbl_theme":"Тема:","theme_dark":"Тёмная","theme_light":"Светлая","col_disk":"Диск","col_model":"Модель","col_type":"Тип","col_bus":"Шина","col_size":"Размер","col_serial":"Серийный №","col_health":"Состояние","col_life":"Ресурс","col_hours":"Часы","col_temp":"Темп.","btn_uefi":"Перезагрузка в настройки UEFI/BIOS","lbl_method":"Метод стирания:","y0":"NIST SP 800-88 Clear  -  Один проход 0x00 (РЕКОМЕНДУЕТСЯ, достаточно для современных накопителей)","y1":"Один проход криптографически случайными данными","y2":"DoD 5220.22-M  -  3 прохода (0x00 / 0xFF / случайные) + проверка","y3":"Расширенный  -  7 проходов (похоже на VSITR, очень медленно)","chk_verify":"Проверять после стирания (считывать данные с диска и сверять)","chk_format":"Сделать диск пригодным к использованию после завершения (создать раздел + быстрое форматирование)","chk_report":"Сохранить отчёт об уничтожении данных (сертификат) в папку отчётов","chk_pdf":"Также создать PDF-сертификат (с кодом проверки; работает вместе с опцией отчёта)","chk_sound":"Воспроизвести звук и мигать окном по завершении","btn_refresh":"Обновить список","btn_speed":"Тест скорости","btn_trace":"Сканирование следов данных","btn_surface":"Тест поверхности","btn_wipe":"БЕЗОПАСНОЕ СТИРАНИЕ","btn_cancel":"Отмена","status_ready":"Готово. Выберите диск(и) для стирания (удерживайте Ctrl для выбора нескольких).","confirm_title":"Подтвердите вводом","confirm_text":"В целях безопасности введите ERASE заглавными буквами в поле ниже, чтобы продолжить:","btn_back":"Назад","btn_startwipe":"НАЧАТЬ СТИРАНИЕ","ready_log":"Strix Disk Cleaner v2.3 готов. Возможности оборудования и данные о состоянии (SMART) запрашиваются автоматически при выборе диска.","protect_log":"ЗАЩИТНЫЙ ЩИТ АКТИВЕН: диск, содержащий {0}, и все загрузочные/системные диски никогда не могут быть выбраны целью; проверки идентичности повторяются во время стирания.","first_disk_select":"Сначала выберите диск из списка.","protect_block_log":"ЗАЩИТНЫЙ ЩИТ ЗАБЛОКИРОВАЛ: {0}","protect_block_msg":"ЗАЩИТНЫЙ ЩИТ задействован:\n\n{0}\n\nЭтот диск никогда не может быть стёрт.","protect_block_title":"Strix Disk Cleaner - Защита системного диска","summary_start":"ВСЕ ДАННЫЕ НА СЛЕДУЮЩИХ {0} ДИСКАХ БУДУТ БЕЗВОЗВРАТНО УНИЧТОЖЕНЫ:","summary_disk":"  Диск {0}: {1}  |  {2}  |  {3} ({4})  |  Серийный №: {5}","summary_method":"Метод: {0}","summary_final":"Это НЕВОЗМОЖНО отменить. Продолжить?","final_warning_title":"ПОСЛЕДНЕЕ ПРЕДУПРЕЖДЕНИЕ","confirm_none_log":"Операция отменена пользователем (подтверждение не получено).","cancel_question":"Вы уверены, что хотите отменить?\nДиск останется частично стёртым (в несогласованном состоянии).","cancel_title":"Подтверждение отмены","cancel_question_read":"Вы уверены, что хотите отменить операцию тестирования поверхности/сканирования?\nДанные не были затронуты; операция будет просто прервана.","t_speed":"Скорость: {0}/с","t_remaining":"Осталось (оценка): {0}","wipe_started_log":"Начато безопасное стирание диска {0}. Метод: {1}","queue_log":"В очередь поставлено {0} дисков; они будут стёрты один за другим.","queue_next_log":"Переход к следующему диску в очереди: Диск {0}...","queue_cancel_log":"Оставшиеся диски в очереди были пропущены из-за ошибки/отмены.","done_msg":"Готово!\n\nВсе данные на {0} диске(ах) были необратимо уничтожены в соответствии с выбранным стандартом.","report_msg":"\n\nОтчёт(ы) сохранён(ы) в папку отчётов.","success_title":"Strix Disk Cleaner - Успех","speed_started_log":"Тест скорости начат: Диск {0} ({1}) - фаза чтения всегда безопасна; фаза записи по возможности использует временный файл.","speed_phase1":"Тест скорости: последовательное чтение... {0}","speed_phase2":"Тест скорости: случайное чтение 4K...","speed_read_summary":"Чтение : последовательное {0}/с  |  случайное 4K {1:N0} IOPS (среднее {2:N1} мс)","speed_write_summary":"Запись: последовательная {0}/с  |  случайная 4K {1:N0} IOPS (среднее {2:N1} мс)","speed_write_raw_summary":"Запись: последовательная {0}/с  (низкоуровневый режим; фаза случайной записи пропущена)","speed_phase3":"Тест скорости: последовательная запись... {0}","speed_phase4":"Тест скорости: случайная запись 4K...","speed_write_file_log":"Цель теста записи: временный файл на {0}: (без разрушения данных, удаляется после).","speed_write_raw_question":"На этом диске нет смонтированного тома с достаточным свободным местом для БЕЗОПАСНОГО теста записи.\nСкорость записи можно измерить только путём ПЕРЕЗАПИСИ первых {0} диска тестовыми данными - всё, что хранится в этой области, будет УНИЧТОЖЕНО.\n\nПродолжить разрушающий низкоуровневый тест записи?","speed_write_none":"Тест записи пропущен.","speed_done_log":"Тест скорости завершён. {0}","speed_note":"Примечание: результаты записи на основе файлов включают накладные расходы файловой системы, поэтому могут быть немного ниже низкоуровневой скорости устройства.","speed_status":"Тест скорости завершён. Результаты в журнале.","speed_msg":"Диск {0} ({1})\n\n{2}","speed_title":"Strix Disk Cleaner - Тест скорости","speed_error_log":"ОШИБКА теста скорости: {0}","trace_started_log":"Сканирование следов данных начато: Диск {0} - выборка только для чтения.","trace_status":"Сканирование следов данных (чтение случайных образцов)...","trace_summary":"Образцы: {0} блоков  |  Содержат следы данных: {1} ({2}%)  |  Обнулённые (пустые): {3}  |  0xFF: {4}  |  Средняя энтропия: {5:N2} бит/байт","trace_note_empty":"Диск выглядит в основном пустым/обнулённым.","trace_note_present":"Присутствуют ВОССТАНАВЛИВАЕМЫЕ СЛЕДЫ ДАННЫХ - перед утилизацией рекомендуется безопасное стирание.","trace_note_encrypted":"Высокая энтропия: данные могут быть зашифрованы/сжаты; безопасное стирание всё же рекомендуется.","trace_title":"Strix Disk Cleaner - Сканирование следов данных","trace_error_log":"ОШИБКА сканирования следов данных: {0}","surface_question":"Тест поверхности считывает ВЕСЬ диск; для {0} это может занять много времени в зависимости от скорости диска.\nДанные не затрагиваются. Начать?","surface_title":"Тест поверхности","surface_started_log":"Тест поверхности начат: Диск {0} ({1}) - вся поверхность будет просканирована только для чтения.","surface_ok_msg":"Тест поверхности завершён.\n\nНечитаемые блоки не обнаружены - поверхность выглядит исправной.","surface_bad_msg":"Тест поверхности завершён.\n\nВНИМАНИЕ: обнаружено {0} нечитаемых блоков по 64 KB!\nПервые местоположения (смещения в байтах):\n{1}\n\nЭтот диск непригоден для надёжного хранения данных.","pdf_ok_log":"PDF-сертификат создан: {0}","pdf_html_log":"Конвертер PDF (Edge) не найден; сохранён HTML-сертификат: {0} (откройте его в браузере и распечатайте в PDF с помощью Ctrl+P).","pdf_error_log":"Не удалось создать PDF-сертификат: {0}","theme_dil_question":"Приложение перезапустится, чтобы применить это изменение. Продолжить?","theme_dil_title":"Требуется перезапуск","busy_msg":"Эту настройку нельзя изменить во время выполнения операции.","temp_fmt":"Температура: {0} C (пик: {1} C)","temp_report":"Темп. во время стирания : зафиксирован пик {0} C","uefi_question":"Компьютер перезагрузится напрямую в настройки UEFI/BIOS через 5 секунд.\nВы сохранили открытые файлы? (Работает только в системах UEFI.)","uefi_title":"Перезагрузка в UEFI/BIOS","health_panel":"СОСТОЯНИЕ / SMART:","m_op_started":"Операция начата: Диск {0} ({1}), {2} GB","m_method":"Метод: {0}","m_protect_ok":"Защитный щит: идентичность целевого диска проверена - это НЕ системный диск, не содержит {0}.","m_status_partition":"Очистка таблицы разделов...","m_cleardisk_note":"Примечание: предупреждение Clear-Disk ({0}) - продолжаем.","m_raw_error":"Не удалось открыть низкоуровневый доступ к диску (ошибка Win32: {0}). Закройте программы, использующие диск, и повторите попытку.","m_status_write":"Запись на диск...","m_pass_fmt":"Проход {0} / {1}  ({2})","m_pass_start":"Проход {0}/{1} начат (шаблон: {2}).","m_pass_done":"Проход {0}/{1} завершён.","m_random":"случайные","m_status_verify":"Проверка (обратное считывание с диска)...","m_verification_label":"Проверка","m_dv_fail":"ПРОВЕРКА НЕ ПРОЙДЕНА: ожидаемый шаблон не найден в {0} проверенных блоках!","m_dv_ok_pattern":"ПРОЙДЕНА ({0} контрольных точек сверено с шаблоном)","m_dv_ok_rand":"ПРОЙДЕНА ({0} контрольных точек считано обратно; последний проход был случайным, поэтому сравнение с шаблоном не применяется)","m_dv_log":"Проверка: {0}","m_notdone":"Не выполнялась","m_status_format":"Повторная подготовка диска (раздел + форматирование)...","m_format_log":"Создание нового раздела и быстрое форматирование...","m_disk_ready":"Диск готов: отформатирован как диск {0}: ({1}).","m_status_trim":"Отправка TRIM (уведомление контроллера о свободных блоках)...","m_trim_start":"Обнаружен SSD: выполняется Optimize-Volume -ReTrim...","m_trim_ok":"TRIM завершён: контроллеру также дано указание освободить устаревшие блоки в своей таблице соответствия.","m_trim_error":"Шаг TRIM пропущен: {0}","m_trim_none_partition":"Примечание: для TRIM нужен том; ReTrim не был применён, так как опция подготовки диска отключена.","m_format_skipped":"Форматирование пропущено: {0} (Вы можете инициализировать диск вручную в оснастке «Управление дисками».)","m_report_saved":"Отчёт об уничтожении сохранён: {0}","m_status_done":"ЗАВЕРШЕНО - Данные необратимо уничтожены.","m_op_ok":"Операция успешно завершена.","m_cancel":"Операция отменена пользователем. ВНИМАНИЕ: диск может быть частично стёрт; данные в несогласованном состоянии.","m_cancel_read":"Сканирование отменено пользователем (данные не были затронуты).","m_error":"ОШИБКА: {0}","m_k_boot":"ЗАЩИТА ({0}): Целевой диск в данный момент оказался ЗАГРУЗОЧНЫМ - операция остановлена!","m_k_system":"ЗАЩИТА ({0}): Целевой диск содержит раздел SYSTEM/EFI - операция остановлена!","m_k_serial_match":"ЗАЩИТА ({0}): Серийный номер целевого диска совпадает с защищённым системным диском - операция остановлена!","m_k_num":"ЗАЩИТА ({0}): Номер целевого диска находится в защищённом списке - операция остановлена!","m_k_serial_changed":"ЗАЩИТА ({0}): Идентичность диска ИЗМЕНИЛАСЬ! Подтверждённый серийный номер {1}, обнаружен {2}. Возможно, устройства были перенумерованы - остановлено в целях безопасности.","m_k_size":"ЗАЩИТА ({0}): Размер диска не совпадает с подтверждённым (ожидалось {1}, обнаружено {2}) - операция остановлена.","m_k_c":"ЗАЩИТА ({0}): Целевой диск содержит том {1} - операция остановлена!","m_y_status":"Сканирование поверхности (только чтение)...","m_y_error":"Нечитаемая область: начиная со смещения {0}, {1} сбойных подблоков по 64 KB.","m_y_ok":"Тест поверхности завершён: нечитаемые блоки не обнаружены.","m_y_done":"Тест поверхности завершён: {0} нечитаемых блоков по 64 KB.","m_trim_applied":"Применено - свободные блоки переданы контроллеру","m_trim_notapplied":"Не применено","r_template":"=====================================================================\n                ОТЧЁТ / СЕРТИФИКАТ ОБ УНИЧТОЖЕНИИ ДАННЫХ\n=====================================================================\nСоздано           : Strix Disk Cleaner v2.3\nДата отчёта       : {0}\nКомпьютер         : {1}  (Пользователь: {2})\n\n--- УНИЧТОЖЕННЫЙ НОСИТЕЛЬ ---\nНомер диска       : {3}\nМодель            : {4}\nСерийный номер    : {5}\nЁмкость           : {6} GB ({7} байт)\nТип носителя      : {8}  |  Шина: {9}\nОбнаружен         : {10}\nСостояние до стир.: {11}\n\n--- ПРИМЕНЁННЫЙ МЕТОД ---\nСтандарт / Метод  : {12}\nКол-во проходов   : {13}\nВсего записано    : {14} GB\nПроверка          : {15}\nTRIM (ReTrim)     : {16}\nДлительность      : {17} мин {18} с\nРезультат         : УСПЕХ - каждый сектор носителя был перезаписан.\n\nПРИМЕЧАНИЕ (NIST SP 800-88 Rev.1): Перезапись обеспечивает уровень Clear.\nДля уровня Purge на носителях SSD/NVMe требуется дополнительный шаг:\n{19}\n=====================================================================","s_healthy":"Исправен","s_warning":"ВНИМАНИЕ","s_unhealthy":"НЕИСПРАВЕН","s_status":"Статус: {0}","s_wear":"Износ: {0}% (оценочный остаточный ресурс ~{1}%)","s_wear_none":"Данные об износе не предоставлены","s_hours":"Наработка: {0:N0} часов (~{1:N0} дней)","s_temp":"Температура: {0} C","s_temp_max":" (максимум зафиксирован: {0} C)","s_errors":"Ошибки: чтение {0} (неисправимых: {1}), запись {2} (неисправимых: {3})","s_smart":"Прогноз отказа SMART: {0}","s_smart_bad":"ПРОГНОЗИРУЕТСЯ ОТКАЗ - СДЕЛАЙТЕ РЕЗЕРВНУЮ КОПИЮ НЕМЕДЛЕННО!","s_smart_good":"Норма (отказ не прогнозируется)","s_counter_none":"Счётчики надёжности недоступны для этого диска/шины.","s_query_none":"Запрос состояния не удался (USB-корпуса/мосты обычно не передают данные SMART).","cert_title":"СЕРТИФИКАТ ОБ УНИЧТОЖЕНИИ ДАННЫХ","cert_sub":"Безопасное уничтожение данных в соответствии с NIST SP 800-88 Rev.1","cert_verification":"Код проверки (SHA-256 отчёта)","cert_field_disk":"Диск","cert_field_serial":"Серийный №","cert_field_capacity":"Ёмкость","cert_field_method":"Метод","cert_field_pass":"Проходы","cert_field_dv":"Проверка","cert_field_duration":"Длительность","cert_field_date":"Дата","cert_field_pc":"Компьютер","cert_field_health":"Состояние до стирания","cert_field_result":"Результат","cert_field_temp":"Пиковая температура","cert_result":"УСПЕХ - все секторы перезаписаны","lbl_report_folder":"Папка отчётов:","btn_report_folder":"Изменить...","report_folder_title":"Выберите, куда сохранять отчёты/сертификаты","chk_eject":"Безопасно извлекать USB-диски по завершении","chk_task":"Показывать ход стирания на значке панели задач","hpa_none":"Скрытая область (HPA/DCO) отсутствует: вся физическая ёмкость доступна для адресации.","hpa_present":"ОБНАРУЖЕНА СКРЫТАЯ ОБЛАСТЬ (HPA/DCO): {0} этого диска ({1} секторов) скрыты от ОС и НЕ будут перезаписаны. Для полного уничтожения используйте фирменную утилиту производителя или аппаратный Secure Erase (см. README).","hpa_query_none":"Проверка скрытой области (HPA/DCO) недоступна на этой шине (USB-мосты обычно блокируют команды ATA).","preview_title":"Содержимое диска (предпросмотр только для чтения)","preview_empty":"На этом диске не обнаружено смонтированных томов / разделов.","preview_partition":"  {0}: {1}  |  использовано {2} из {3} ({4}% заполнено)  |  {5}","preview_partition_noletter":"  Раздел {0}: {1}  (без буквы диска)","preview_summary":"На этом диске {0} раздел(ов), всего около {1} данных.","preview_title_panel":"СОДЕРЖИМОЕ:","smart_title":"Атрибуты SMART - Диск {0}","smart_col_name":"Атрибут","smart_col_value":"Значение","smart_col_worst":"Худшее","smart_col_raw":"Необраб.","smart_col_status":"Статус","smart_none":"Таблица необработанных атрибутов SMART недоступна для этого диска (USB-мост или NVMe - сводка о состоянии выше по-прежнему актуальна).","smart_btn":"Подробности SMART","smart_check":"ПРОВЕРИТЬ","eject_ok":"USB-диск {0} извлечён - теперь его можно безопасно отключить.","eject_error":"Автоматическое извлечение не удалось ({0}); используйте значок «Безопасное извлечение устройств» в области уведомлений.","trace_note_clean":"Диск по сути пуст - обнаружены только структуры разделов (восстанавливаемых пользовательских данных нет).","lbl_language":"Язык:","already_running":"Strix Disk Cleaner уже запущен."},
"sv":{"window_title":"Strix Disk Cleaner v2.3 - Professionellt verktyg för dataförstöring","sub_title":"NIST SP 800-88- och DoD 5220.22-M-kompatibel, oåterkallelig disktorkning","lbl_theme":"Tema:","theme_dark":"Mörkt","theme_light":"Ljust","col_model":"Modell","col_type":"Typ","col_bus":"Buss","col_size":"Storlek","col_serial":"Serienr","col_health":"Hälsa","col_life":"Livslängd","col_hours":"Timmar","btn_uefi":"Starta om till UEFI/BIOS-inställningar","lbl_method":"Torkningsmetod:","y0":"NIST SP 800-88 Clear  -  Ett svep 0x00 (REKOMMENDERAS, tillräckligt för moderna diskar)","y1":"Ett svep med kryptografiskt slumpmässiga data","y2":"DoD 5220.22-M  -  3 svep (0x00 / 0xFF / slumpmässigt) + verifiering","y3":"Avancerad  -  7 svep (VSITR-liknande, mycket långsam)","chk_verify":"Verifiera efter torkning (läs tillbaka från disken och kontrollera)","chk_format":"Gör disken användbar när det är klart (skapa partition + snabbformatering)","chk_report":"Spara en dataförstöringsrapport (certifikat) i rapportmappen","chk_pdf":"Skapa även ett PDF-certifikat (med verifieringskod; fungerar med rapportalternativet)","chk_sound":"Spela upp ett ljud och blinka fönstret när det är klart","btn_refresh":"Uppdatera listan","btn_speed":"Hastighetstest","btn_trace":"Skanning efter dataspår","btn_surface":"Yttest","btn_wipe":"SÄKER RADERING","btn_cancel":"Avbryt","status_ready":"Klart. Välj disk(ar) att torka (håll ned Ctrl för att välja flera).","confirm_title":"Bekräfta genom att skriva","confirm_text":"Skriv av säkerhetsskäl ERASE med versaler i rutan nedan för att fortsätta:","btn_back":"Tillbaka","btn_startwipe":"STARTA TORKNING","ready_log":"Strix Disk Cleaner v2.3 klar. Hårdvarukapacitet och hälsodata (SMART) hämtas automatiskt när du väljer en disk.","protect_log":"SKYDDSSKÖLD AKTIV: disken som innehåller {0} och alla start-/systemdiskar kan aldrig väljas som mål; identitetskontroller upprepas under torkningen.","first_disk_select":"Välj först en disk i listan.","protect_block_log":"SKYDDSSKÖLD BLOCKERADE: {0}","protect_block_msg":"SKYDDSSKÖLD aktiverad:\n\n{0}\n\nDenna disk kan aldrig torkas.","protect_block_title":"Strix Disk Cleaner - Systemdiskskydd","summary_start":"ALLA DATA PÅ FÖLJANDE {0} DISK(AR) KOMMER ATT FÖRSTÖRAS PERMANENT:","summary_disk":"  Disk {0}: {1}  |  {2}  |  {3} ({4})  |  Serienr: {5}","summary_method":"Metod: {0}","summary_final":"Detta kan INTE ångras. Fortsätta?","final_warning_title":"SISTA VARNINGEN","confirm_none_log":"Åtgärden avbröts av användaren (bekräftelse gavs inte).","cancel_question":"Är du säker på att du vill avbryta?\nDisken kommer att lämnas delvis torkad (inkonsekvent).","cancel_title":"Bekräfta avbrytning","cancel_question_read":"Är du säker på att du vill avbryta yt-/skanningsåtgärden?\nData har inte rörts; åtgärden avbryts bara.","t_speed":"Hastighet: {0}/s","t_remaining":"Beräknad återstående tid: {0}","wipe_started_log":"Säker torkning startad för disk {0}. Metod: {1}","queue_log":"{0} diskar i kö; de torkas en efter en.","queue_next_log":"Går vidare till nästa disk i kön: Disk {0}...","queue_cancel_log":"Återstående diskar i kön hoppades över på grund av fel/avbrytning.","done_msg":"Klart!\n\nAlla data på {0} disk(ar) förstördes oåterkalleligt enligt vald standard.","report_msg":"\n\nRapport(er) sparade i rapportmappen.","success_title":"Strix Disk Cleaner - Lyckades","speed_started_log":"Hastighetstest startat: Disk {0} ({1}) - läsfasen är alltid säker; skrivfasen använder en tillfällig fil när det är möjligt.","speed_phase1":"Hastighetstest: sekventiell läsning... {0}","speed_phase2":"Hastighetstest: slumpmässig 4K-läsning...","speed_read_summary":"Läsning  : sekventiell {0}/s  |  slumpmässig 4K {1:N0} IOPS (snitt {2:N1} ms)","speed_write_summary":"Skrivning: sekventiell {0}/s  |  slumpmässig 4K {1:N0} IOPS (snitt {2:N1} ms)","speed_write_raw_summary":"Skrivning: sekventiell {0}/s  (råläge; slumpmässig skrivfas hoppades över)","speed_phase3":"Hastighetstest: sekventiell skrivning... {0}","speed_phase4":"Hastighetstest: slumpmässig 4K-skrivning...","speed_write_file_log":"Skrivtestets mål: tillfällig fil på {0}: (icke-förstörande, tas bort efteråt).","speed_write_raw_question":"Denna disk har ingen monterad volym med tillräckligt ledigt utrymme för ett SÄKERT skrivtest.\nSkrivhastigheten kan endast mätas genom att SKRIVA ÖVER de första {0} av disken med testdata - allt som lagras i det området kommer att FÖRSTÖRAS.\n\nFortsätta med det förstörande råskrivtestet?","speed_write_none":"Skrivtestet hoppades över.","speed_done_log":"Hastighetstest slutfört. {0}","speed_note":"Obs: filbaserade skrivresultat inkluderar filsystemets omkostnader, så de kan visa något lägre än råenhetens hastighet.","speed_status":"Hastighetstest slutfört. Resultaten finns i loggen.","speed_title":"Strix Disk Cleaner - Hastighetstest","speed_error_log":"Hastighetstest-FEL: {0}","trace_started_log":"Skanning efter dataspår startad: Disk {0} - skrivskyddad sampling.","trace_status":"Skannar efter dataspår (läser slumpmässiga prover)...","trace_summary":"Prover: {0} block  |  Innehåller dataspår: {1} ({2}%)  |  Nollställda (tomma): {3}  |  0xFF: {4}  |  Snittentropi: {5:N2} bitar/byte","trace_note_empty":"Disken verkar till stor del tom/nollställd.","trace_note_present":"ÅTERSTÄLLNINGSBARA DATASPÅR finns - säker torkning rekommenderas före kassering.","trace_note_encrypted":"Hög entropi: data kan vara krypterade/komprimerade; säker torkning rekommenderas ändå.","trace_title":"Strix Disk Cleaner - Skanning efter dataspår","trace_error_log":"Skanning efter dataspår-FEL: {0}","surface_question":"Yttestet läser HELA disken; för {0} kan detta ta lång tid beroende på diskhastighet.\nData rörs inte. Starta?","surface_title":"Yttest","surface_started_log":"Yttest startat: Disk {0} ({1}) - hela ytan skannas skrivskyddat.","surface_ok_msg":"Yttest slutfört.\n\nInga oläsbara block hittades - ytan ser frisk ut.","surface_bad_msg":"Yttest slutfört.\n\nVARNING: {0} oläsbara 64 KB-block hittades!\nFörsta platser (byte-förskjutningar):\n{1}\n\nDenna disk är inte lämplig för tillförlitlig lagring.","pdf_ok_log":"PDF-certifikat skapat: {0}","pdf_html_log":"PDF-omvandlare (Edge) hittades inte; HTML-certifikat sparat: {0} (öppna det i en webbläsare och skriv ut till PDF med Ctrl+P).","pdf_error_log":"PDF-certifikatet kunde inte skapas: {0}","theme_dil_question":"Programmet startas om för att tillämpa ändringen. Fortsätta?","theme_dil_title":"Omstart krävs","busy_msg":"Den här inställningen kan inte ändras medan en åtgärd pågår.","temp_fmt":"Temperatur: {0} C (topp: {1} C)","temp_report":"Temp under torkning : topp {0} C uppmätt","uefi_question":"Datorn startar om direkt till UEFI/BIOS-inställningar om 5 sekunder.\nHar du sparat dina öppna filer? (Fungerar endast på UEFI-system.)","uefi_title":"Starta om till UEFI/BIOS","health_panel":"HÄLSA / SMART:","m_op_started":"Åtgärd startad: Disk {0} ({1}), {2} GB","m_method":"Metod: {0}","m_protect_ok":"Skyddssköld: måldiskens identitet verifierad - INTE systemdisken, innehåller inte {0}.","m_status_partition":"Rensar partitionstabellen...","m_cleardisk_note":"Obs: Clear-Disk-varning ({0}) - fortsätter.","m_raw_error":"Rå diskåtkomst kunde inte öppnas (Win32-fel: {0}). Stäng program som använder disken och försök igen.","m_status_write":"Skriver till disken...","m_pass_fmt":"Svep {0} / {1}  ({2})","m_pass_start":"Svep {0}/{1} startat (mönster: {2}).","m_pass_done":"Svep {0}/{1} slutfört.","m_random":"slumpmässigt","m_status_verify":"Verifierar (läser tillbaka från disken)...","m_verification_label":"Verifiering","m_dv_fail":"VERIFIERING MISSLYCKADES: förväntat mönster hittades inte i {0} samplade block!","m_dv_ok_pattern":"GODKÄND ({0} samplingspunkter verifierade mot mönstret)","m_dv_ok_rand":"GODKÄND ({0} samplingspunkter tillbakalästa; sista svepet var slumpmässigt så ingen mönsterjämförelse tillämpas)","m_dv_log":"Verifiering: {0}","m_notdone":"Utfördes inte","m_status_format":"Förbereder disken igen (partition + formatering)...","m_format_log":"Skapar en ny partition och snabbformaterar...","m_disk_ready":"Disken klar: formaterad som enhet {0}: ({1}).","m_status_trim":"Skickar TRIM (meddelar styrenheten om lediga block)...","m_trim_start":"SSD upptäckt: kör Optimize-Volume -ReTrim...","m_trim_ok":"TRIM slutfört: styrenheten instruerades att frigöra inaktuella block även i sin mappningstabell.","m_trim_error":"TRIM-steget hoppades över: {0}","m_trim_none_partition":"Obs: TRIM behöver en volym; ReTrim tillämpades inte eftersom alternativet för att förbereda disken är av.","m_format_skipped":"Formatering hoppades över: {0} (Du kan initiera disken manuellt i Diskhantering.)","m_report_saved":"Förstöringsrapport sparad: {0}","m_status_done":"SLUTFÖRT - Data har förstörts oåterkalleligt.","m_op_ok":"Åtgärden slutfördes.","m_cancel":"Åtgärden avbröts av användaren. VARNING: disken kan vara delvis torkad; data är inkonsekventa.","m_cancel_read":"Skanningen avbröts av användaren (data rördes inte).","m_error":"FEL: {0}","m_k_boot":"SKYDD ({0}): Måldisken verkar för närvarande vara STARTDISKEN - åtgärden stoppad!","m_k_system":"SKYDD ({0}): Måldisken bär SYSTEM-/EFI-partitionen - åtgärden stoppad!","m_k_serial_match":"SKYDD ({0}): Måldiskens serienummer matchar den skyddade systemdisken - åtgärden stoppad!","m_k_num":"SKYDD ({0}): Måldiskens nummer finns på skyddslistan - åtgärden stoppad!","m_k_serial_changed":"SKYDD ({0}): Diskens identitet ÄNDRAD! Bekräftat serienummer {1}, hittade {2}. Enheter kan ha numrerats om - stoppad av säkerhetsskäl.","m_k_size":"SKYDD ({0}): Diskstorleken matchar inte den bekräftade (förväntade {1}, hittade {2}) - åtgärden stoppad.","m_k_c":"SKYDD ({0}): Måldisken är värd för enheten {1} - åtgärden stoppad!","m_y_status":"Skannar ytan (skrivskyddat)...","m_y_error":"Oläsbart område: börjar vid förskjutning {0}, {1} misslyckade 64 KB-delblock.","m_y_ok":"Yttest slutfört: inga oläsbara block hittades.","m_y_done":"Yttest slutfört: {0} oläsbara 64 KB-block.","m_trim_applied":"Tillämpad - lediga block rapporterade till styrenheten","m_trim_notapplied":"Inte tillämpad","r_template":"=====================================================================\n               RAPPORT OM DATAFÖRSTÖRING / CERTIFIKAT\n=====================================================================\nSkapad av         : Strix Disk Cleaner v2.3\nRapportdatum      : {0}\nDator             : {1}  (Användare: {2})\n\n--- FÖRSTÖRT MEDIA ---\nDisknummer        : {3}\nModell            : {4}\nSerienummer       : {5}\nKapacitet         : {6} GB ({7} byte)\nMedietyp          : {8}  |  Buss: {9}\nUpptäckt          : {10}\nHälsa före torkn. : {11}\n\n--- TILLÄMPAD METOD ---\nStandard / Metod  : {12}\nAntal svep        : {13}\nTotalt skrivet    : {14} GB\nVerifiering       : {15}\nTRIM (ReTrim)     : {16}\nVaraktighet       : {17} min {18} s\nResultat          : LYCKADES - varje sektor på mediet skrevs över.\n\nOBS (NIST SP 800-88 Rev.1): Överskrivning ger Clear-nivån.\nFör Purge-nivån på SSD/NVMe-media, ytterligare steg:\n{19}\n=====================================================================","s_healthy":"Frisk","s_warning":"VARNING","s_unhealthy":"EJ FRISK","s_wear":"Slitage: {0}% (uppskattad återstående livslängd ~{1}%)","s_wear_none":"Slitagedata rapporteras inte","s_hours":"Påslagen: {0:N0} timmar (~{1:N0} dagar)","s_temp":"Temperatur: {0} C","s_temp_max":" (högsta uppmätta: {0} C)","s_errors":"Fel: läsning {0} (ej korrigerbara: {1}), skrivning {2} (ej korrigerbara: {3})","s_smart":"SMART-felprognos: {0}","s_smart_bad":"FEL FÖRUTSPÅS - SÄKERHETSKOPIERA NU!","s_smart_good":"Normal (inget fel förutspås)","s_counter_none":"Tillförlitlighetsräknare exponeras inte för denna disk/buss.","s_query_none":"Hälsofrågan misslyckades (USB-kabinett/-bryggor släpper vanligtvis inte igenom SMART-data).","cert_title":"CERTIFIKAT FÖR DATAFÖRSTÖRING","cert_sub":"Säker dataförstöring i enlighet med NIST SP 800-88 Rev.1","cert_verification":"Verifieringskod (rapport-SHA-256)","cert_field_serial":"Serienr","cert_field_capacity":"Kapacitet","cert_field_method":"Metod","cert_field_pass":"Svep","cert_field_dv":"Verifiering","cert_field_duration":"Varaktighet","cert_field_date":"Datum","cert_field_pc":"Dator","cert_field_health":"Hälsa före torkning","cert_field_result":"Resultat","cert_field_temp":"Topptemperatur","cert_result":"LYCKADES - alla sektorer överskrivna","lbl_report_folder":"Rapportmapp:","btn_report_folder":"Ändra...","report_folder_title":"Välj var rapporter/certifikat sparas","chk_eject":"Mata ut USB-diskar säkert när det är klart","chk_task":"Visa torkningsförlopp på aktivitetsfältets ikon","hpa_none":"Inget dolt område (HPA/DCO): hela den fysiska kapaciteten är adresserbar.","hpa_present":"DOLT OMRÅDE UPPTÄCKT (HPA/DCO): {0} av denna disk ({1} sektorer) är dolt för operativsystemet och kommer INTE att skrivas över. För fullständig förstöring, använd tillverkarens verktyg eller en hårdvarubaserad Secure Erase (se README).","hpa_query_none":"Kontroll av dolt område (HPA/DCO) är inte tillgänglig på denna buss (USB-bryggor blockerar vanligtvis ATA-kommandon).","preview_title":"Diskinnehåll (skrivskyddad förhandsvisning)","preview_empty":"Inga monterade volymer/partitioner upptäcktes på denna disk.","preview_partition":"  {0}: {1}  |  {2} av {3} använt ({4}% fullt)  |  {5}","preview_partition_noletter":"  Partition {0}: {1}  (ingen enhetsbeteckning)","preview_summary":"Denna disk har {0} partition(er), totalt cirka {1} data.","preview_title_panel":"INNEHÅLL:","smart_title":"SMART-attribut - Disk {0}","smart_col_name":"Attribut","smart_col_value":"Värde","smart_col_worst":"Sämsta","smart_col_raw":"Rådata","smart_none":"Rå SMART-attributtabell är inte tillgänglig för denna disk (USB-brygga eller NVMe - hälsosammanfattningen ovan gäller ändå).","smart_btn":"SMART-detaljer","smart_check":"KONTROLLERA","eject_ok":"USB-disk {0} utmatad - du kan koppla ur den säkert nu.","eject_error":"Automatisk utmatning misslyckades ({0}); använd ikonen \"Säker borttagning av maskinvara\" i aktivitetsfältet.","trace_note_clean":"Disken är i princip tom - endast partitionsstrukturer hittades (inga återställningsbara användardata).","lbl_language":"Språk:","already_running":"Strix Disk Cleaner körs redan."},
"zh-CN":{"window_title":"Strix Disk Cleaner v2.3 - 专业数据销毁工具","sub_title":"符合 NIST SP 800-88 与 DoD 5220.22-M 标准的不可逆磁盘擦除","lbl_theme":"主题：","theme_dark":"深色","theme_light":"浅色","col_disk":"磁盘","col_model":"型号","col_type":"类型","col_bus":"总线","col_size":"容量","col_serial":"序列号","col_health":"健康度","col_life":"寿命","col_hours":"小时","col_temp":"温度","btn_uefi":"重启进入 UEFI/BIOS 设置","lbl_method":"擦除方式：","y0":"NIST SP 800-88 Clear  -  单次写入 0x00（推荐，对现代硬盘已足够）","y1":"单次写入加密级随机数据","y2":"DoD 5220.22-M  -  3 次（0x00 / 0xFF / random）+ 验证","y3":"高级  -  7 次（类 VSITR，速度很慢）","chk_verify":"擦除后进行验证（从磁盘回读并检查）","chk_format":"完成后使磁盘可用（创建分区 + 快速格式化）","chk_report":"将数据销毁报告（证书）保存到报告文件夹","chk_pdf":"同时生成 PDF 证书（含验证码；需配合报告选项使用）","chk_sound":"完成时播放提示音并闪烁窗口","btn_refresh":"刷新列表","btn_speed":"速度测试","btn_trace":"数据残留扫描","btn_surface":"表面测试","btn_wipe":"安全擦除","btn_cancel":"取消","status_ready":"就绪。请选择要擦除的磁盘（按住 Ctrl 可多选）。","confirm_title":"输入确认","confirm_text":"为安全起见，请在下方框中输入大写的 ERASE 以继续：","btn_back":"返回","btn_startwipe":"开始擦除","ready_log":"Strix Disk Cleaner v2.3 已就绪。选择磁盘时会自动查询硬件功能与健康（SMART）数据。","protect_log":"保护盾已启用：包含 {0} 的磁盘以及所有引导/系统磁盘永远不会成为擦除目标；擦除过程中会反复进行身份校验。","first_disk_select":"请先从列表中选择一个磁盘。","protect_block_log":"保护盾已拦截：{0}","protect_block_msg":"保护盾已生效：\n\n{0}\n\n此磁盘永远不会被擦除。","protect_block_title":"Strix Disk Cleaner - 系统磁盘保护","summary_start":"以下 {0} 个磁盘上的所有数据将被永久销毁：","summary_disk":"  磁盘 {0}：{1}  |  {2}  |  {3} ({4})  |  序列号：{5}","summary_method":"方式：{0}","summary_final":"此操作无法撤销。是否继续？","final_warning_title":"最终警告","confirm_none_log":"操作已被用户取消（未确认）。","cancel_question":"确定要取消吗？\n磁盘将处于部分擦除状态（数据不一致）。","cancel_title":"取消确认","cancel_question_read":"确定要取消表面测试/扫描操作吗？\n数据未被改动；操作只会被中断。","t_speed":"速度：{0}/s","t_remaining":"预计剩余：{0}","wipe_started_log":"已开始对磁盘 {0} 进行安全擦除。方式：{1}","queue_log":"已将 {0} 个磁盘加入队列；它们将依次被擦除。","queue_next_log":"正在切换到队列中的下一个磁盘：磁盘 {0}...","queue_cancel_log":"由于错误/取消，队列中剩余的磁盘已被跳过。","done_msg":"完成！\n\n{0} 个磁盘上的所有数据已按所选标准被不可逆地销毁。","report_msg":"\n\n报告已保存到报告文件夹。","success_title":"Strix Disk Cleaner - 成功","speed_started_log":"速度测试已开始：磁盘 {0} ({1}) - 读取阶段始终安全；写入阶段会尽可能使用临时文件。","speed_phase1":"速度测试：顺序读取... {0}","speed_phase2":"速度测试：随机 4K 读取...","speed_read_summary":"读取：顺序 {0}/s  |  随机 4K {1:N0} IOPS（平均 {2:N1} ms）","speed_write_summary":"写入：顺序 {0}/s  |  随机 4K {1:N0} IOPS（平均 {2:N1} ms）","speed_write_raw_summary":"写入：顺序 {0}/s （原始模式；已跳过随机写入阶段）","speed_phase3":"速度测试：顺序写入... {0}","speed_phase4":"速度测试：随机 4K 写入...","speed_write_file_log":"写入测试目标：{0}: 上的临时文件（非破坏性，测试后删除）。","speed_write_raw_question":"此磁盘没有任何已挂载卷具有足够的可用空间来进行安全的写入测试。\n只能通过用测试数据覆盖磁盘开头的 {0} 来测量写入速度 - 该区域内存储的任何内容都将被销毁。\n\n是否继续进行破坏性的原始写入测试？","speed_write_none":"已跳过写入测试。","speed_done_log":"速度测试已完成。{0}","speed_note":"注意：基于文件的写入结果包含文件系统开销，因此可能略低于设备的原始速度。","speed_status":"速度测试已完成。结果见日志。","speed_msg":"磁盘 {0} ({1})\n\n{2}","speed_title":"Strix Disk Cleaner - 速度测试","speed_error_log":"速度测试错误：{0}","trace_started_log":"数据残留扫描已开始：磁盘 {0} - 只读采样。","trace_status":"正在扫描数据残留（读取随机样本）...","trace_summary":"样本：{0} 个块  |  含数据残留：{1} ({2}%)  |  已置零（空白）：{3}  |  0xFF：{4}  |  平均熵：{5:N2} bits/byte","trace_note_empty":"磁盘看起来基本为空白/已置零。","trace_note_present":"存在可恢复的数据残留 - 建议在处置前进行安全擦除。","trace_note_encrypted":"高熵：数据可能已加密/压缩；仍建议进行安全擦除。","trace_title":"Strix Disk Cleaner - 数据残留扫描","trace_error_log":"数据残留扫描错误：{0}","surface_question":"表面测试将读取整个磁盘；对于 {0}，视磁盘速度而定，这可能需要较长时间。\n数据不会被改动。是否开始？","surface_title":"表面测试","surface_started_log":"表面测试已开始：磁盘 {0} ({1}) - 将以只读方式扫描整个表面。","surface_ok_msg":"表面测试已完成。\n\n未发现不可读的块 - 表面状况良好。","surface_bad_msg":"表面测试已完成。\n\n警告：发现 {0} 个不可读的 64 KB 块！\n首批位置（字节偏移）：\n{1}\n\n此磁盘不适合用于可靠存储。","pdf_ok_log":"已生成 PDF 证书：{0}","pdf_html_log":"未找到 PDF 转换器（Edge）；已保存 HTML 证书：{0}（在浏览器中打开，并用 Ctrl+P 打印为 PDF）。","pdf_error_log":"无法生成 PDF 证书：{0}","theme_dil_question":"应用程序将重启以应用此更改。是否继续？","theme_dil_title":"需要重启","busy_msg":"操作正在运行时无法更改此设置。","temp_fmt":"温度：{0} C（峰值：{1} C）","temp_report":"擦除期间温度  : 测得峰值 {0} C","uefi_question":"计算机将在 5 秒后直接重启进入 UEFI/BIOS 设置。\n您是否已保存打开的文件？（仅适用于 UEFI 系统。）","uefi_title":"重启进入 UEFI/BIOS","health_panel":"健康度 / SMART：","m_op_started":"操作已开始：磁盘 {0} ({1})，{2} GB","m_method":"方式：{0}","m_protect_ok":"保护盾：已验证目标磁盘身份 - 并非系统磁盘，不包含 {0}。","m_status_partition":"正在清除分区表...","m_cleardisk_note":"注意：Clear-Disk 警告 ({0}) - 继续执行。","m_raw_error":"无法打开磁盘的原始访问（Win32 错误：{0}）。请关闭正在使用该磁盘的程序后重试。","m_status_write":"正在写入磁盘...","m_pass_fmt":"第 {0} / {1} 次  ({2})","m_pass_start":"第 {0}/{1} 次已开始（模式：{2}）。","m_pass_done":"第 {0}/{1} 次已完成。","m_random":"随机","m_status_verify":"正在验证（从磁盘回读）...","m_verification_label":"验证","m_dv_fail":"验证失败：在 {0} 个采样块中未找到预期模式！","m_dv_ok_pattern":"通过（已对 {0} 个采样点与模式进行比对）","m_dv_ok_rand":"通过（已回读 {0} 个采样点；最后一次为随机写入，故不适用模式比对）","m_dv_log":"验证：{0}","m_notdone":"未执行","m_status_format":"正在重新准备磁盘（分区 + 格式化）...","m_format_log":"正在创建新分区并快速格式化...","m_disk_ready":"磁盘已就绪：已格式化为驱动器 {0}: ({1})。","m_status_trim":"正在发送 TRIM（向控制器通知空闲块）...","m_trim_start":"检测到 SSD：正在运行 Optimize-Volume -ReTrim...","m_trim_ok":"TRIM 已完成：已通知控制器同时释放其映射表中的陈旧块。","m_trim_error":"已跳过 TRIM 步骤：{0}","m_trim_none_partition":"注意：TRIM 需要卷；由于准备磁盘选项已关闭，未执行 ReTrim。","m_format_skipped":"已跳过格式化：{0}（您可以在磁盘管理中手动初始化该磁盘。）","m_report_saved":"销毁报告已保存：{0}","m_status_done":"已完成 - 数据已被不可逆地销毁。","m_op_ok":"操作已成功完成。","m_cancel":"操作已被用户取消。警告：磁盘可能已被部分擦除；数据不一致。","m_cancel_read":"扫描已被用户取消（数据未被改动）。","m_error":"错误：{0}","m_k_boot":"保护 ({0})：目标磁盘目前似乎是引导磁盘 - 操作已停止！","m_k_system":"保护 ({0})：目标磁盘含有 SYSTEM/EFI 分区 - 操作已停止！","m_k_serial_match":"保护 ({0})：目标磁盘序列号与受保护的系统磁盘一致 - 操作已停止！","m_k_num":"保护 ({0})：目标磁盘编号在受保护列表中 - 操作已停止！","m_k_serial_changed":"保护 ({0})：磁盘身份已变更！确认的序列号为 {1}，实际找到 {2}。设备可能已被重新编号 - 为安全起见已停止。","m_k_size":"保护 ({0})：磁盘容量与已确认的不符（预期 {1}，实际 {2}）- 操作已停止。","m_k_c":"保护 ({0})：目标磁盘承载 {1} 驱动器 - 操作已停止！","m_y_status":"正在扫描表面（只读）...","m_y_error":"不可读区域：从偏移 {0} 开始，{1} 个 64 KB 子块失败。","m_y_ok":"表面测试已完成：未发现不可读的块。","m_y_done":"表面测试已完成：{0} 个不可读的 64 KB 块。","m_trim_applied":"已执行 - 空闲块已上报给控制器","m_trim_notapplied":"未执行","r_template":"=====================================================================\n                数据销毁报告 / 证书\n=====================================================================\n创建者            : Strix Disk Cleaner v2.3\n报告日期          : {0}\n计算机            : {1}  (用户: {2})\n\n--- 已销毁介质 ---\n磁盘编号          : {3}\n型号              : {4}\n序列号            : {5}\n容量              : {6} GB ({7} 字节)\n介质类型          : {8}  |  总线: {9}\n检测到            : {10}\n擦除前健康度      : {11}\n\n--- 已应用方式 ---\n标准 / 方式       : {12}\n次数              : {13}\n总写入量          : {14} GB\n验证              : {15}\nTRIM (ReTrim)     : {16}\n耗时              : {17} 分 {18} 秒\n结果              : 成功 - 介质的每个扇区均已被覆盖。\n\n注意 (NIST SP 800-88 Rev.1)：覆盖写入提供 Clear（清除）级别。\n对于 SSD/NVMe 介质要达到 Purge（清理）级别，附加步骤：\n{19}\n=====================================================================","s_healthy":"健康","s_warning":"警告","s_unhealthy":"不健康","s_status":"状态：{0}","s_wear":"磨损：{0}%（估计剩余寿命约 {1}%）","s_wear_none":"未报告磨损数据","s_hours":"通电时间：{0:N0} 小时（约 {1:N0} 天）","s_temp":"温度：{0} C","s_temp_max":"（观测最高值：{0} C）","s_errors":"错误：读 {0}（不可纠正：{1}），写 {2}（不可纠正：{3}）","s_smart":"SMART 故障预测：{0}","s_smart_bad":"预测将发生故障 - 请立即备份！","s_smart_good":"正常（未预测到故障）","s_counter_none":"此磁盘/总线未提供可靠性计数器。","s_query_none":"健康查询失败（USB 硬盘盒/桥接器通常不会传递 SMART 数据）。","cert_title":"数据销毁证书","cert_sub":"符合 NIST SP 800-88 Rev.1 的安全数据销毁","cert_verification":"验证码（报告 SHA-256）","cert_field_disk":"磁盘","cert_field_serial":"序列号","cert_field_capacity":"容量","cert_field_method":"方式","cert_field_pass":"次数","cert_field_dv":"验证","cert_field_duration":"耗时","cert_field_date":"日期","cert_field_pc":"计算机","cert_field_health":"擦除前健康度","cert_field_result":"结果","cert_field_temp":"峰值温度","cert_result":"成功 - 所有扇区均已覆盖","lbl_report_folder":"报告文件夹：","btn_report_folder":"更改...","report_folder_title":"选择报告/证书的保存位置","chk_eject":"完成后安全弹出 USB 磁盘","chk_task":"在任务栏图标上显示擦除进度","hpa_none":"无隐藏区域（HPA/DCO）：完整的物理容量均可寻址。","hpa_present":"检测到隐藏区域（HPA/DCO）：此磁盘中的 {0}（{1} 个扇区）对操作系统隐藏，将不会被覆盖。要彻底销毁，请使用厂商工具或硬件 Secure Erase（参见 README）。","hpa_query_none":"此总线不支持隐藏区域（HPA/DCO）检查（USB 桥接器通常会阻止 ATA 命令）。","preview_title":"磁盘内容（只读预览）","preview_empty":"此磁盘上未检测到已挂载的卷/分区。","preview_partition":"  {0}: {1}  |  已用 {2}/{3}（占用 {4}%）  |  {5}","preview_partition_noletter":"  分区 {0}：{1} （无驱动器号）","preview_summary":"此磁盘有 {0} 个分区，数据总量约 {1}。","preview_title_panel":"内容：","smart_title":"SMART 属性 - 磁盘 {0}","smart_col_name":"属性","smart_col_value":"当前值","smart_col_worst":"最差值","smart_col_raw":"原始值","smart_col_status":"状态","smart_none":"此磁盘无法提供原始 SMART 属性表（USB 桥接器或 NVMe - 上方的健康摘要仍然适用）。","smart_btn":"SMART 详情","smart_ok":"正常","smart_check":"需检查","eject_ok":"USB 磁盘 {0} 已弹出 - 现在可以安全拔出。","eject_error":"自动弹出失败 ({0})；请使用任务栏的“安全删除硬件”图标。","trace_note_clean":"磁盘基本为空白 - 仅发现分区结构（无可恢复的用户数据）。","lbl_language":"语言：","already_running":"Strix Disk Cleaner 已在运行。"},
"ja":{"window_title":"Strix Disk Cleaner v2.3 - プロフェッショナルデータ破壊ツール","sub_title":"NIST SP 800-88 および DoD 5220.22-M 準拠の復元不可能なディスク消去","lbl_theme":"テーマ:","theme_dark":"ダーク","theme_light":"ライト","col_disk":"ディスク","col_model":"モデル","col_type":"種類","col_bus":"バス","col_size":"サイズ","col_serial":"シリアル番号","col_health":"健全性","col_life":"寿命","col_hours":"時間","col_temp":"温度","btn_uefi":"UEFI/BIOS 設定で再起動","lbl_method":"消去方式:","y0":"NIST SP 800-88 Clear  -  1 パス 0x00（推奨、最新のドライブには十分）","y1":"暗号的乱数データによる 1 パス","y2":"DoD 5220.22-M  -  3 パス（0x00 / 0xFF / ランダム）＋ 検証","y3":"アドバンスト  -  7 パス（VSITR 相当、非常に低速）","chk_verify":"消去後に検証する（ディスクから読み戻して確認）","chk_format":"完了時にディスクを使用可能にする（パーティション作成＋クイックフォーマット）","chk_report":"データ破壊レポート（証明書）をレポートフォルダーに保存する","chk_pdf":"PDF 証明書も作成する（検証コード付き。レポートオプションと併用）","chk_sound":"完了時にサウンドを鳴らしウィンドウを点滅させる","btn_refresh":"一覧を更新","btn_speed":"速度テスト","btn_trace":"データ痕跡スキャン","btn_surface":"表面テスト","btn_wipe":"セキュア消去","btn_cancel":"キャンセル","status_ready":"準備完了。消去するディスクを選択してください（複数選択するには Ctrl を押しながら）。","confirm_title":"入力して確認","confirm_text":"安全のため、続行するには下のボックスに大文字で ERASE と入力してください:","btn_back":"戻る","btn_startwipe":"消去を開始","ready_log":"Strix Disk Cleaner v2.3 の準備が完了しました。ディスクを選択すると、ハードウェア機能と健全性（SMART）データが自動的に照会されます。","protect_log":"保護シールド有効: {0} を含むディスクおよびすべての起動/システムディスクは決して対象にできません。消去中も識別チェックが繰り返し行われます。","first_disk_select":"先に一覧からディスクを選択してください。","protect_block_log":"保護シールドがブロックしました: {0}","protect_block_msg":"保護シールドが作動しました:\n\n{0}\n\nこのディスクは決して消去できません。","protect_block_title":"Strix Disk Cleaner - システムディスク保護","summary_start":"以下の {0} 台のディスク上のすべてのデータが完全に破壊されます:","summary_disk":"  ディスク {0}: {1}  |  {2}  |  {3} ({4})  |  シリアル: {5}","summary_method":"方式: {0}","summary_final":"この操作は元に戻せません。続行しますか？","final_warning_title":"最終警告","confirm_none_log":"ユーザーによって操作がキャンセルされました（確認が行われませんでした）。","cancel_question":"本当にキャンセルしますか？\nディスクは部分的に消去された（不整合な）状態のままになります。","cancel_title":"キャンセルの確認","cancel_question_read":"表面/スキャン操作をキャンセルしますか？\nデータには手を加えていません。操作が中断されるだけです。","t_speed":"速度: {0}/秒","t_remaining":"残り時間の目安: {0}","wipe_started_log":"ディスク {0} のセキュア消去を開始しました。方式: {1}","queue_log":"{0} 台のディスクをキューに追加しました。順番に消去されます。","queue_next_log":"キュー内の次のディスクに移動します: ディスク {0}...","queue_cancel_log":"エラー/キャンセルのため、キュー内の残りのディスクはスキップされました。","done_msg":"完了しました！\n\n{0} 台のディスク上のすべてのデータが、選択した規格に従って復元不可能な形で破壊されました。","report_msg":"\n\nレポートをレポートフォルダーに保存しました。","success_title":"Strix Disk Cleaner - 成功","speed_started_log":"速度テストを開始しました: ディスク {0} ({1}) - 読み取りフェーズは常に安全です。書き込みフェーズは可能な場合は一時ファイルを使用します。","speed_phase1":"速度テスト: シーケンシャル読み取り... {0}","speed_phase2":"速度テスト: ランダム 4K 読み取り...","speed_read_summary":"読み取り: シーケンシャル {0}/秒  |  ランダム 4K {1:N0} IOPS（平均 {2:N1} ms）","speed_write_summary":"書き込み: シーケンシャル {0}/秒  |  ランダム 4K {1:N0} IOPS（平均 {2:N1} ms）","speed_write_raw_summary":"書き込み: シーケンシャル {0}/秒  （raw モード。ランダム書き込みフェーズはスキップ）","speed_phase3":"速度テスト: シーケンシャル書き込み... {0}","speed_phase4":"速度テスト: ランダム 4K 書き込み...","speed_write_file_log":"書き込みテスト対象: {0}: 上の一時ファイル（非破壊的で、後で削除されます）。","speed_write_raw_question":"このディスクには、安全な書き込みテストに十分な空き容量を持つマウント済みボリュームがありません。\n書き込み速度を測定するには、ディスクの先頭 {0} をテストデータで上書きするしかありません。その領域に保存されているデータは破壊されます。\n\n破壊的な raw 書き込みテストを実行しますか？","speed_write_none":"書き込みテストをスキップしました。","speed_done_log":"速度テストが完了しました。{0}","speed_note":"注: ファイルベースの書き込み結果にはファイルシステムのオーバーヘッドが含まれるため、raw デバイス速度をわずかに下回ることがあります。","speed_status":"速度テストが完了しました。結果はログにあります。","speed_msg":"ディスク {0} ({1})\n\n{2}","speed_title":"Strix Disk Cleaner - 速度テスト","speed_error_log":"速度テストエラー: {0}","trace_started_log":"データ痕跡スキャンを開始しました: ディスク {0} - 読み取り専用サンプリング。","trace_status":"データ痕跡をスキャン中（ランダムサンプルを読み取り中）...","trace_summary":"サンプル: {0} ブロック  |  データ痕跡を含む: {1} ({2}%)  |  ゼロ埋め（空白）: {3}  |  0xFF: {4}  |  平均エントロピー: {5:N2} bits/byte","trace_note_empty":"ディスクはほぼ空白/ゼロ埋めの状態のようです。","trace_note_present":"復元可能なデータ痕跡が存在します - 廃棄前にセキュア消去を推奨します。","trace_note_encrypted":"高エントロピー: データは暗号化/圧縮されている可能性があります。それでもセキュア消去を推奨します。","trace_title":"Strix Disk Cleaner - データ痕跡スキャン","trace_error_log":"データ痕跡スキャンエラー: {0}","surface_question":"表面テストはディスク全体を読み取ります。{0} の場合、ディスク速度によっては長時間かかることがあります。\nデータには手を加えません。開始しますか？","surface_title":"表面テスト","surface_started_log":"表面テストを開始しました: ディスク {0} ({1}) - 表面全体を読み取り専用でスキャンします。","surface_ok_msg":"表面テストが完了しました。\n\n読み取り不能なブロックは見つかりませんでした - 表面は健全なようです。","surface_bad_msg":"表面テストが完了しました。\n\n警告: {0} 個の読み取り不能な 64 KB ブロックが見つかりました！\n最初の位置（バイトオフセット）:\n{1}\n\nこのディスクは信頼できるストレージには適していません。","pdf_ok_log":"PDF 証明書を作成しました: {0}","pdf_html_log":"PDF コンバーター（Edge）が見つかりません。HTML 証明書を保存しました: {0}（ブラウザーで開き、Ctrl+P で PDF に印刷してください）。","pdf_error_log":"PDF 証明書を作成できませんでした: {0}","theme_dil_question":"この変更を適用するためにアプリケーションを再起動します。続行しますか？","theme_dil_title":"再起動が必要です","busy_msg":"操作の実行中はこの設定を変更できません。","temp_fmt":"温度: {0} C（ピーク: {1} C）","temp_report":"消去中の温度  : ピーク {0} C を測定","uefi_question":"コンピューターは 5 秒後に UEFI/BIOS 設定へ直接再起動します。\n開いているファイルは保存しましたか？（UEFI システムでのみ動作します。）","uefi_title":"UEFI/BIOS で再起動","health_panel":"健全性 / SMART:","m_op_started":"操作を開始しました: ディスク {0} ({1})、{2} GB","m_method":"方式: {0}","m_protect_ok":"保護シールド: 対象ディスクの識別を確認しました - システムディスクではなく、{0} を含みません。","m_status_partition":"パーティションテーブルを消去中...","m_cleardisk_note":"注: Clear-Disk の警告 ({0}) - 続行します。","m_raw_error":"raw ディスクアクセスを開けませんでした（Win32 エラー: {0}）。ディスクを使用しているプログラムを閉じて、再試行してください。","m_status_write":"ディスクに書き込み中...","m_pass_fmt":"パス {0} / {1}  ({2})","m_pass_start":"パス {0}/{1} を開始しました（パターン: {2}）。","m_pass_done":"パス {0}/{1} が完了しました。","m_random":"ランダム","m_status_verify":"検証中（ディスクから読み戻し中）...","m_verification_label":"検証","m_dv_fail":"検証に失敗しました: {0} 個のサンプルブロックで期待されたパターンが見つかりませんでした！","m_dv_ok_pattern":"合格（{0} 個のサンプルポイントをパターンと照合して検証）","m_dv_ok_rand":"合格（{0} 個のサンプルポイントを読み戻し。最後のパスはランダムのためパターン比較は適用されません）","m_dv_log":"検証: {0}","m_notdone":"実施していません","m_status_format":"ディスクを再準備中（パーティション＋フォーマット）...","m_format_log":"新しいパーティションを作成し、クイックフォーマット中...","m_disk_ready":"ディスクの準備完了: ドライブ {0}: ({1}) としてフォーマットしました。","m_status_trim":"TRIM を送信中（空きブロックをコントローラーに通知中）...","m_trim_start":"SSD を検出: Optimize-Volume -ReTrim を実行中...","m_trim_ok":"TRIM が完了しました: コントローラーにマッピングテーブル内の古いブロックの解放も指示しました。","m_trim_error":"TRIM 手順をスキップしました: {0}","m_trim_none_partition":"注: TRIM にはボリュームが必要です。ディスク準備オプションがオフのため、ReTrim は適用されませんでした。","m_format_skipped":"フォーマットをスキップしました: {0}（ディスクの管理で手動でディスクを初期化できます。）","m_report_saved":"破壊レポートを保存しました: {0}","m_status_done":"完了 - データは復元不可能な形で破壊されました。","m_op_ok":"操作が正常に完了しました。","m_cancel":"ユーザーによって操作がキャンセルされました。警告: ディスクは部分的に消去されている可能性があり、データは不整合です。","m_cancel_read":"ユーザーによってスキャンがキャンセルされました（データには手を加えていません）。","m_error":"エラー: {0}","m_k_boot":"保護 ({0}): 対象ディスクは現在ブートディスクであると思われます - 操作を停止しました！","m_k_system":"保護 ({0}): 対象ディスクにはシステム/EFI パーティションが含まれています - 操作を停止しました！","m_k_serial_match":"保護 ({0}): 対象ディスクのシリアルが保護対象のシステムディスクと一致します - 操作を停止しました！","m_k_num":"保護 ({0}): 対象ディスク番号が保護リストに含まれています - 操作を停止しました！","m_k_serial_changed":"保護 ({0}): ディスクの識別情報が変化しました！確認済みシリアルは {1} ですが、{2} が見つかりました。デバイスの番号が再割り当てされた可能性があります - 安全のため停止しました。","m_k_size":"保護 ({0}): ディスクサイズが確認済みのものと一致しません（期待値 {1}、検出値 {2}） - 操作を停止しました。","m_k_c":"保護 ({0}): 対象ディスクには {1} ドライブが存在します - 操作を停止しました！","m_y_status":"表面をスキャン中（読み取り専用）...","m_y_error":"読み取り不能な領域: オフセット {0} から開始、{1} 個の 64 KB サブブロックが失敗。","m_y_ok":"表面テストが完了しました: 読み取り不能なブロックは見つかりませんでした。","m_y_done":"表面テストが完了しました: {0} 個の読み取り不能な 64 KB ブロック。","m_trim_applied":"適用済み - 空きブロックをコントローラーに報告しました","m_trim_notapplied":"未適用","r_template":"=====================================================================\n                     データ破壊レポート / 証明書\n=====================================================================\n作成ツール      : Strix Disk Cleaner v2.3\nレポート日時    : {0}\nコンピューター  : {1}  (ユーザー: {2})\n\n--- 破壊されたメディア ---\nディスク番号    : {3}\nモデル          : {4}\nシリアル番号    : {5}\n容量            : {6} GB ({7} バイト)\nメディアの種類  : {8}  |  バス: {9}\n検出            : {10}\n消去前の健全性  : {11}\n\n--- 適用された方式 ---\n規格 / 方式     : {12}\nパス回数        : {13}\n合計書き込み量  : {14} GB\n検証            : {15}\nTRIM (ReTrim)   : {16}\n所要時間        : {17} 分 {18} 秒\n結果            : 成功 - メディアのすべてのセクターが上書きされました。\n\n注 (NIST SP 800-88 Rev.1): 上書きは Clear レベルを提供します。\nSSD/NVMe メディアで Purge レベルにするには、追加手順:\n{19}\n=====================================================================","s_healthy":"正常","s_warning":"警告","s_unhealthy":"異常","s_status":"状態: {0}","s_wear":"摩耗: {0}%（推定残り寿命 約 {1}%）","s_wear_none":"摩耗データは報告されていません","s_hours":"通電時間: {0:N0} 時間（約 {1:N0} 日）","s_temp":"温度: {0} C","s_temp_max":" （最高値: {0} C）","s_errors":"エラー: 読み取り {0}（訂正不能: {1}）、書き込み {2}（訂正不能: {3}）","s_smart":"SMART 故障予測: {0}","s_smart_bad":"故障が予測されています - 今すぐバックアップしてください！","s_smart_good":"正常（故障は予測されていません）","s_counter_none":"このディスク/バスでは信頼性カウンターが公開されていません。","s_query_none":"健全性の照会に失敗しました（USB エンクロージャー/ブリッジは通常 SMART データを通しません）。","cert_title":"データ破壊証明書","cert_sub":"NIST SP 800-88 Rev.1 準拠のセキュアなデータ破壊","cert_verification":"検証コード（レポートの SHA-256）","cert_field_disk":"ディスク","cert_field_serial":"シリアル番号","cert_field_capacity":"容量","cert_field_method":"方式","cert_field_pass":"パス回数","cert_field_dv":"検証","cert_field_duration":"所要時間","cert_field_date":"日付","cert_field_pc":"コンピューター","cert_field_health":"消去前の健全性","cert_field_result":"結果","cert_field_temp":"ピーク温度","cert_result":"成功 - すべてのセクターを上書き","lbl_report_folder":"レポートフォルダー:","btn_report_folder":"変更...","report_folder_title":"レポート/証明書の保存先を選択","chk_eject":"完了時に USB ディスクを安全に取り外す","chk_task":"タスクバーアイコンに消去の進行状況を表示する","hpa_none":"隠し領域なし（HPA/DCO）: 物理容量全体にアクセス可能です。","hpa_present":"隠し領域を検出しました（HPA/DCO）: このディスクの {0}（{1} セクター）は OS から隠されており、上書きされません。完全に破壊するには、メーカーのツールまたはハードウェアの Secure Erase を使用してください（README を参照）。","hpa_query_none":"このバスでは隠し領域（HPA/DCO）チェックは利用できません（USB ブリッジは通常 ATA コマンドをブロックします）。","preview_title":"ディスクの内容（読み取り専用プレビュー）","preview_empty":"このディスクにはマウントされたボリューム/パーティションが検出されませんでした。","preview_partition":"  {0}: {1}  |  {3} 中 {2} 使用済み（{4}% 使用）  |  {5}","preview_partition_noletter":"  パーティション {0}: {1}  （ドライブ文字なし）","preview_summary":"このディスクには {0} 個のパーティションがあり、合計で約 {1} のデータがあります。","preview_title_panel":"内容:","smart_title":"SMART 属性 - ディスク {0}","smart_col_name":"属性","smart_col_value":"値","smart_col_worst":"最悪値","smart_col_raw":"生の値","smart_col_status":"状態","smart_none":"このディスクでは生の SMART 属性テーブルを利用できません（USB ブリッジまたは NVMe - 上記の健全性サマリーは引き続き有効です）。","smart_btn":"SMART の詳細","smart_check":"要確認","eject_ok":"USB ディスク {0} を取り外しました - 安全に抜くことができます。","eject_error":"自動取り外しに失敗しました（{0}）。トレイの「ハードウェアの安全な取り外し」アイコンを使用してください。","trace_note_clean":"ディスクは実質的に空です - パーティション構造のみが見つかりました（復元可能なユーザーデータはありません）。","lbl_language":"言語:","already_running":"Strix Disk Cleaner は既に実行中です。"},
"ko":{"window_title":"Strix Disk Cleaner v2.3 - 전문가용 데이터 파기 도구","sub_title":"NIST SP 800-88 및 DoD 5220.22-M 준수, 복구 불가능한 디스크 완전 삭제","lbl_theme":"테마:","theme_dark":"어두운 테마","theme_light":"밝은 테마","col_disk":"디스크","col_model":"모델","col_type":"유형","col_bus":"버스","col_size":"용량","col_serial":"일련번호","col_health":"상태","col_life":"수명","col_hours":"가동 시간","col_temp":"온도","btn_uefi":"UEFI/BIOS 설정으로 다시 시작","lbl_method":"삭제 방식:","y0":"NIST SP 800-88 Clear  -  0x00 단일 패스 (권장, 최신 드라이브에 충분함)","y1":"암호학적 난수 데이터 단일 패스","y2":"DoD 5220.22-M  -  3 패스 (0x00 / 0xFF / 난수) + 검증","y3":"고급  -  7 패스 (VSITR 방식, 매우 느림)","chk_verify":"삭제 후 검증 (디스크에서 다시 읽어 확인)","chk_format":"완료 후 디스크를 사용 가능하게 만들기 (파티션 생성 + 빠른 포맷)","chk_report":"데이터 파기 보고서(인증서)를 보고서 폴더에 저장","chk_pdf":"PDF 인증서도 생성 (검증 코드 포함, 보고서 옵션과 함께 작동)","chk_sound":"완료 시 소리를 재생하고 창을 깜박이기","btn_refresh":"목록 새로 고침","btn_speed":"속도 테스트","btn_trace":"데이터 흔적 검사","btn_surface":"표면 검사","btn_wipe":"보안 삭제","btn_cancel":"취소","status_ready":"준비 완료. 삭제할 디스크를 선택하세요 (여러 개를 선택하려면 Ctrl을 누른 채로).","confirm_title":"입력하여 확인","confirm_text":"안전을 위해 계속하려면 아래 상자에 ERASE를 대문자로 입력하세요:","btn_back":"뒤로","btn_startwipe":"삭제 시작","ready_log":"Strix Disk Cleaner v2.3 준비 완료. 디스크를 선택하면 하드웨어 기능과 상태(SMART) 데이터가 자동으로 조회됩니다.","protect_log":"보호막 활성화됨: {0}이(가) 있는 디스크와 모든 부팅/시스템 디스크는 절대 대상이 될 수 없습니다. 삭제 중에도 식별 검사가 반복됩니다.","first_disk_select":"먼저 목록에서 디스크를 선택하세요.","protect_block_log":"보호막 차단됨: {0}","protect_block_msg":"보호막 작동됨:\n\n{0}\n\n이 디스크는 절대 삭제할 수 없습니다.","protect_block_title":"Strix Disk Cleaner - 시스템 디스크 보호","summary_start":"다음 {0}개 디스크의 모든 데이터가 영구적으로 파기됩니다:","summary_disk":"  디스크 {0}: {1}  |  {2}  |  {3} ({4})  |  일련번호: {5}","summary_method":"방식: {0}","summary_final":"이 작업은 되돌릴 수 없습니다. 계속하시겠습니까?","final_warning_title":"최종 경고","confirm_none_log":"사용자가 작업을 취소했습니다 (확인이 제공되지 않음).","cancel_question":"정말 취소하시겠습니까?\n디스크가 부분적으로만 삭제되어 (불일치 상태) 남게 됩니다.","cancel_title":"취소 확인","cancel_question_read":"표면/검사 작업을 정말 취소하시겠습니까?\n데이터는 변경되지 않았으며, 작업이 단순히 중단됩니다.","t_speed":"속도: {0}/s","t_remaining":"예상 남은 시간: {0}","wipe_started_log":"디스크 {0}에 대한 보안 삭제가 시작되었습니다. 방식: {1}","queue_log":"{0}개 디스크가 대기열에 추가되었습니다. 차례대로 삭제됩니다.","queue_next_log":"대기열의 다음 디스크로 이동 중: 디스크 {0}...","queue_cancel_log":"오류/취소로 인해 대기열의 나머지 디스크는 건너뛰었습니다.","done_msg":"완료!\n\n{0}개 디스크의 모든 데이터가 선택한 표준에 따라 복구 불가능하게 파기되었습니다.","report_msg":"\n\n보고서가 보고서 폴더에 저장되었습니다.","success_title":"Strix Disk Cleaner - 성공","speed_started_log":"속도 테스트 시작됨: 디스크 {0} ({1}) - 읽기 단계는 항상 안전하며, 쓰기 단계는 가능한 경우 임시 파일을 사용합니다.","speed_phase1":"속도 테스트: 순차 읽기... {0}","speed_phase2":"속도 테스트: 무작위 4K 읽기...","speed_read_summary":"읽기 : 순차 {0}/s  |  무작위 4K {1:N0} IOPS (평균 {2:N1} ms)","speed_write_summary":"쓰기: 순차 {0}/s  |  무작위 4K {1:N0} IOPS (평균 {2:N1} ms)","speed_write_raw_summary":"쓰기: 순차 {0}/s  (RAW 모드, 무작위 쓰기 단계 건너뜀)","speed_phase3":"속도 테스트: 순차 쓰기... {0}","speed_phase4":"속도 테스트: 무작위 4K 쓰기...","speed_write_file_log":"쓰기 테스트 대상: {0}:의 임시 파일 (비파괴적, 이후 삭제됨).","speed_write_raw_question":"이 디스크에는 안전한 쓰기 테스트에 충분한 여유 공간을 가진 마운트된 볼륨이 없습니다.\n쓰기 속도는 디스크의 처음 {0}을(를) 테스트 데이터로 덮어써야만 측정할 수 있으며, 해당 영역에 저장된 내용은 모두 파기됩니다.\n\n파괴적인 RAW 쓰기 테스트를 진행하시겠습니까?","speed_write_none":"쓰기 테스트를 건너뛰었습니다.","speed_done_log":"속도 테스트가 완료되었습니다. {0}","speed_note":"참고: 파일 기반 쓰기 결과에는 파일 시스템 오버헤드가 포함되므로, RAW 장치 속도보다 약간 낮게 측정될 수 있습니다.","speed_status":"속도 테스트가 완료되었습니다. 결과는 로그에 있습니다.","speed_msg":"디스크 {0} ({1})\n\n{2}","speed_title":"Strix Disk Cleaner - 속도 테스트","speed_error_log":"속도 테스트 오류: {0}","trace_started_log":"데이터 흔적 검사 시작됨: 디스크 {0} - 읽기 전용 샘플링.","trace_status":"데이터 흔적 검사 중 (무작위 샘플 읽기)...","trace_summary":"샘플: {0}개 블록  |  데이터 흔적 포함: {1}개 ({2}%)  |  0으로 채워짐(빈): {3}개  |  0xFF: {4}개  |  평균 엔트로피: {5:N2} bits/byte","trace_note_empty":"디스크가 대체로 비어 있거나 0으로 채워진 것으로 보입니다.","trace_note_present":"복구 가능한 데이터 흔적이 존재합니다 - 폐기 전에 보안 삭제를 권장합니다.","trace_note_encrypted":"높은 엔트로피: 데이터가 암호화/압축되었을 수 있습니다. 그래도 보안 삭제를 권장합니다.","trace_title":"Strix Disk Cleaner - 데이터 흔적 검사","trace_error_log":"데이터 흔적 검사 오류: {0}","surface_question":"표면 검사는 디스크 전체를 읽으므로, {0}의 경우 디스크 속도에 따라 오랜 시간이 걸릴 수 있습니다.\n데이터는 변경되지 않습니다. 시작하시겠습니까?","surface_title":"표면 검사","surface_started_log":"표면 검사 시작됨: 디스크 {0} ({1}) - 전체 표면을 읽기 전용으로 검사합니다.","surface_ok_msg":"표면 검사가 완료되었습니다.\n\n읽을 수 없는 블록이 발견되지 않았습니다 - 표면이 정상으로 보입니다.","surface_bad_msg":"표면 검사가 완료되었습니다.\n\n경고: 읽을 수 없는 64 KB 블록이 {0}개 발견되었습니다!\n첫 번째 위치 (바이트 오프셋):\n{1}\n\n이 디스크는 신뢰할 수 있는 저장에 적합하지 않습니다.","pdf_ok_log":"PDF 인증서가 생성되었습니다: {0}","pdf_html_log":"PDF 변환기(Edge)를 찾을 수 없어 HTML 인증서를 저장했습니다: {0} (브라우저에서 열어 Ctrl+P로 PDF로 인쇄하세요).","pdf_error_log":"PDF 인증서를 생성할 수 없습니다: {0}","theme_dil_question":"이 변경 사항을 적용하기 위해 애플리케이션이 다시 시작됩니다. 계속하시겠습니까?","theme_dil_title":"다시 시작 필요","busy_msg":"작업이 실행 중일 때는 이 설정을 변경할 수 없습니다.","temp_fmt":"온도: {0} C (최고: {1} C)","temp_report":"삭제 중 온도  : 최고 {0} C 측정됨","uefi_question":"컴퓨터가 5초 후에 UEFI/BIOS 설정으로 바로 다시 시작됩니다.\n열려 있는 파일을 저장하셨습니까? (UEFI 시스템에서만 작동합니다.)","uefi_title":"UEFI/BIOS로 다시 시작","health_panel":"상태 / SMART:","m_op_started":"작업 시작됨: 디스크 {0} ({1}), {2} GB","m_method":"방식: {0}","m_protect_ok":"보호막: 대상 디스크 식별이 확인됨 - 시스템 디스크가 아니며, {0}을(를) 포함하지 않습니다.","m_status_partition":"파티션 테이블 지우는 중...","m_cleardisk_note":"참고: Clear-Disk 경고 ({0}) - 계속 진행합니다.","m_raw_error":"RAW 디스크 액세스를 열 수 없습니다 (Win32 오류: {0}). 디스크를 사용 중인 프로그램을 닫고 다시 시도하세요.","m_status_write":"디스크에 쓰는 중...","m_pass_fmt":"패스 {0} / {1}  ({2})","m_pass_start":"패스 {0}/{1} 시작됨 (패턴: {2}).","m_pass_done":"패스 {0}/{1} 완료됨.","m_random":"난수","m_status_verify":"검증 중 (디스크에서 다시 읽는 중)...","m_verification_label":"검증","m_dv_fail":"검증 실패: 샘플링한 {0}개 블록에서 예상 패턴을 찾을 수 없습니다!","m_dv_ok_pattern":"통과 ({0}개 샘플 지점이 패턴과 대조하여 검증됨)","m_dv_ok_rand":"통과 ({0}개 샘플 지점을 다시 읽음. 마지막 패스가 난수였으므로 패턴 비교는 적용되지 않음)","m_dv_log":"검증: {0}","m_notdone":"수행되지 않음","m_status_format":"디스크를 다시 준비하는 중 (파티션 + 포맷)...","m_format_log":"새 파티션을 생성하고 빠른 포맷 중...","m_disk_ready":"디스크 준비 완료: 드라이브 {0}:로 포맷됨 ({1}).","m_status_trim":"TRIM 전송 중 (컨트롤러에 여유 블록 알림)...","m_trim_start":"SSD 감지됨: Optimize-Volume -ReTrim 실행 중...","m_trim_ok":"TRIM 완료: 컨트롤러가 매핑 테이블의 오래된 블록도 해제하도록 지시받았습니다.","m_trim_error":"TRIM 단계를 건너뛰었습니다: {0}","m_trim_none_partition":"참고: TRIM에는 볼륨이 필요합니다. 디스크 준비 옵션이 꺼져 있어 ReTrim이 적용되지 않았습니다.","m_format_skipped":"포맷을 건너뛰었습니다: {0} (디스크 관리에서 디스크를 수동으로 초기화할 수 있습니다.)","m_report_saved":"파기 보고서가 저장되었습니다: {0}","m_status_done":"완료됨 - 데이터가 복구 불가능하게 파기되었습니다.","m_op_ok":"작업이 성공적으로 완료되었습니다.","m_cancel":"사용자가 작업을 취소했습니다. 경고: 디스크가 부분적으로 삭제되었을 수 있으며, 데이터가 불일치 상태입니다.","m_cancel_read":"사용자가 검사를 취소했습니다 (데이터는 변경되지 않음).","m_error":"오류: {0}","m_k_boot":"보호 ({0}): 대상 디스크가 현재 부팅 디스크로 보입니다 - 작업이 중지되었습니다!","m_k_system":"보호 ({0}): 대상 디스크에 시스템/EFI 파티션이 있습니다 - 작업이 중지되었습니다!","m_k_serial_match":"보호 ({0}): 대상 디스크의 일련번호가 보호된 시스템 디스크와 일치합니다 - 작업이 중지되었습니다!","m_k_num":"보호 ({0}): 대상 디스크 번호가 보호 목록에 있습니다 - 작업이 중지되었습니다!","m_k_serial_changed":"보호 ({0}): 디스크 식별이 변경되었습니다! 확인된 일련번호는 {1}이지만 {2}이(가) 발견되었습니다. 장치 번호가 다시 매겨졌을 수 있어 안전을 위해 중지되었습니다.","m_k_size":"보호 ({0}): 디스크 용량이 확인된 값과 일치하지 않습니다 (예상 {1}, 발견 {2}) - 작업이 중지되었습니다.","m_k_c":"보호 ({0}): 대상 디스크에 {1} 드라이브가 있습니다 - 작업이 중지되었습니다!","m_y_status":"표면 검사 중 (읽기 전용)...","m_y_error":"읽을 수 없는 영역: 오프셋 {0}에서 시작, {1}개의 64 KB 하위 블록 실패.","m_y_ok":"표면 검사 완료: 읽을 수 없는 블록이 발견되지 않았습니다.","m_y_done":"표면 검사 완료: 읽을 수 없는 64 KB 블록 {0}개.","m_trim_applied":"적용됨 - 여유 블록이 컨트롤러에 보고됨","m_trim_notapplied":"적용되지 않음","r_template":"=====================================================================\n                데이터 파기 보고서 / 인증서\n=====================================================================\n작성 도구          : Strix Disk Cleaner v2.3\n보고서 날짜        : {0}\n컴퓨터             : {1}  (사용자: {2})\n\n--- 파기된 매체 ---\n디스크 번호        : {3}\n모델               : {4}\n일련번호           : {5}\n용량               : {6} GB ({7} bytes)\n매체 유형          : {8}  |  버스: {9}\n감지됨             : {10}\n삭제 전 상태       : {11}\n\n--- 적용된 방식 ---\n표준 / 방식        : {12}\n패스 횟수          : {13}\n총 기록량          : {14} GB\n검증               : {15}\nTRIM (ReTrim)     : {16}\n소요 시간          : {17}분 {18}초\n결과               : 성공 - 매체의 모든 섹터를 덮어썼습니다.\n\n참고 (NIST SP 800-88 Rev.1): 덮어쓰기는 Clear 수준을 제공합니다.\nSSD/NVMe 매체의 Purge 수준을 위해서는 추가 단계:\n{19}\n=====================================================================","s_healthy":"정상","s_warning":"경고","s_unhealthy":"비정상","s_status":"상태: {0}","s_wear":"마모도: {0}% (예상 남은 수명 약 {1}%)","s_wear_none":"마모 데이터가 보고되지 않음","s_hours":"전원 켜짐: {0:N0}시간 (약 {1:N0}일)","s_temp":"온도: {0} C","s_temp_max":" (최고 측정값: {0} C)","s_errors":"오류: 읽기 {0} (복구 불가: {1}), 쓰기 {2} (복구 불가: {3})","s_smart":"SMART 고장 예측: {0}","s_smart_bad":"고장 예측됨 - 지금 백업하세요!","s_smart_good":"정상 (고장이 예측되지 않음)","s_counter_none":"이 디스크/버스에서는 신뢰성 카운터가 노출되지 않습니다.","s_query_none":"상태 조회 실패 (USB 인클로저/브리지는 보통 SMART 데이터를 전달하지 않습니다).","cert_title":"데이터 파기 인증서","cert_sub":"NIST SP 800-88 Rev.1 준수 보안 데이터 파기","cert_verification":"검증 코드 (보고서 SHA-256)","cert_field_disk":"디스크","cert_field_serial":"일련번호","cert_field_capacity":"용량","cert_field_method":"방식","cert_field_pass":"패스 횟수","cert_field_dv":"검증","cert_field_duration":"소요 시간","cert_field_date":"날짜","cert_field_pc":"컴퓨터","cert_field_health":"삭제 전 상태","cert_field_result":"결과","cert_field_temp":"최고 온도","cert_result":"성공 - 모든 섹터를 덮어씀","lbl_report_folder":"보고서 폴더:","btn_report_folder":"변경...","report_folder_title":"보고서/인증서가 저장될 위치를 선택하세요","chk_eject":"완료 시 USB 디스크를 안전하게 꺼내기","chk_task":"작업 표시줄 아이콘에 삭제 진행률 표시","hpa_none":"숨겨진 영역 없음 (HPA/DCO): 전체 물리적 용량에 접근할 수 있습니다.","hpa_present":"숨겨진 영역 감지됨 (HPA/DCO): 이 디스크의 {0} ({1} 섹터)이(가) OS에서 숨겨져 있어 덮어쓰이지 않습니다. 완전한 파기를 위해서는 제조사 도구나 하드웨어 Secure Erase를 사용하세요 (README 참조).","hpa_query_none":"이 버스에서는 숨겨진 영역 (HPA/DCO) 검사를 사용할 수 없습니다 (USB 브리지는 보통 ATA 명령을 차단합니다).","preview_title":"디스크 내용 (읽기 전용 미리 보기)","preview_empty":"이 디스크에서 마운트된 볼륨/파티션이 감지되지 않았습니다.","preview_partition":"  {0}: {1}  |  {3} 중 {2} 사용됨 ({4}% 채워짐)  |  {5}","preview_partition_noletter":"  파티션 {0}: {1}  (드라이브 문자 없음)","preview_summary":"이 디스크에는 {0}개의 파티션이 있으며, 총 약 {1}의 데이터가 있습니다.","preview_title_panel":"내용:","smart_title":"SMART 속성 - 디스크 {0}","smart_col_name":"속성","smart_col_value":"값","smart_col_worst":"최악값","smart_col_raw":"원시값","smart_col_status":"상태","smart_none":"이 디스크에서는 원시 SMART 속성 테이블을 사용할 수 없습니다 (USB 브리지 또는 NVMe - 위의 상태 요약은 여전히 유효합니다).","smart_btn":"SMART 세부 정보","smart_ok":"정상","smart_check":"확인 필요","eject_ok":"USB 디스크 {0}이(가) 꺼내졌습니다 - 이제 안전하게 분리할 수 있습니다.","eject_error":"자동 꺼내기에 실패했습니다 ({0}). 트레이의 \"하드웨어 안전하게 제거\" 아이콘을 사용하세요.","trace_note_clean":"디스크는 사실상 비어 있습니다 - 파티션 구조만 발견되었습니다 (복구 가능한 사용자 데이터 없음).","lbl_language":"언어:","already_running":"Strix Disk Cleaner가 이미 실행 중입니다."}
}
'@
# <I18N-DATA-END>
try {
    $parsed = $script:I18nData | ConvertFrom-Json
    foreach ($langProp in $parsed.PSObject.Properties) {
        $h = @{}
        foreach ($k in $script:Languages.en.Keys) { $h[$k] = $script:Languages.en[$k] }   # complete English baseline
        foreach ($kv in $langProp.Value.PSObject.Properties) {
            if ($h.ContainsKey($kv.Name) -and -not [string]::IsNullOrEmpty([string]$kv.Value)) { $h[$kv.Name] = [string]$kv.Value }
        }
        $script:Languages[$langProp.Name] = $h
    }
} catch { }

if (-not $script:Languages.ContainsKey([string]$script:Settings.Language)) { $script:Settings.Language = 'en' }
$script:Text = $script:Languages[[string]$script:Settings.Language]
function T([string]$k) {
    $v = $script:Text[$k]
    if ($null -eq $v) { $v = $k }
    return [string]$v
}
function Expand-Xaml([string]$template) {
    $s = $template
    foreach ($k in $script:Theme.Keys)  { $s = $s.Replace('%' + $k + '%', [string]$script:Theme[$k]) }
    foreach ($k in $script:Text.Keys) {
        $v = [string]$script:Text[$k]
        # Security: text values are always XML-escaped before being embedded into XAML
        $v = $v.Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('"','&quot;')
        $s = $s.Replace('{T:' + $k + '}', $v)
    }
    return [xml]$s
}

# ---- Single-instance lock: prevent two copies running at once (localized message) --
# Placed after the language is resolved so the notice appears in the user's language.
$script:singleInstanceNew = $false
$script:singleInstance = New-Object System.Threading.Mutex($true, 'Local\StrixDiskCleaner_Single', [ref]$script:singleInstanceNew)
if (-not $script:singleInstanceNew) {
    [System.Windows.MessageBox]::Show((T 'already_running'), 'Strix Disk Cleaner', 'OK', 'Information') | Out-Null
    exit
}

# ---- Notification: sound + window flash -----------------------------------
if (-not ('GsFlash' -as [type])) {
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class GsFlash {
    [StructLayout(LayoutKind.Sequential)]
    struct FLASHWINFO { public uint cbSize; public IntPtr hwnd; public uint dwFlags; public uint uCount; public uint dwTimeout; }
    [DllImport("user32.dll")] static extern bool FlashWindowEx(ref FLASHWINFO pwfi);
    public static void Flash(IntPtr h) {
        FLASHWINFO f = new FLASHWINFO();
        f.cbSize = (uint)Marshal.SizeOf(typeof(FLASHWINFO));
        f.hwnd = h; f.dwFlags = 15; f.uCount = 6; f.dwTimeout = 0;   // FLASHW_ALL | FLASHW_TIMERNOFG
        FlashWindowEx(ref f);
    }
}
"@
}
if (-not ('GsAnalyze' -as [type])) {
Add-Type -TypeDefinition @"
using System;
public static class GsAnalyze {
    // Inspects one block: [0]=code (0=all 0x00, 1=all 0xFF, 2=data), [1]=Shannon entropy (bits/byte)
    public static double[] Inspect(byte[] b, int n) {
        if (n <= 0) return new double[] { 0.0, 0.0 };
        bool allZero = true, allFF = true;
        int[] counter = new int[256];
        for (int i = 0; i < n; i++) {
            byte v = b[i];
            if (v != 0x00) allZero = false;
            if (v != 0xFF) allFF = false;
            counter[v]++;
        }
        double code = allZero ? 0.0 : (allFF ? 1.0 : 2.0);
        double entropy = 0.0;
        for (int i = 0; i < 256; i++) {
            if (counter[i] == 0) continue;
            double p = (double)counter[i] / n;
            entropy -= p * (Math.Log(p) / Math.Log(2.0));
        }
        return new double[] { code, entropy };
    }
}
"@
}
# ---- Embedded app icon (base64 .ico: 16/20/24/32/40/48/64) -------------
$script:IconB64 = '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'

function Show-Notification([bool]$success) {
    $soundOn = $script:Settings.Sound
    try { if ($null -ne $chkSound) { $soundOn = [bool]$chkSound.IsChecked } } catch { }
    if (-not $soundOn) { return }
    try {
        if ($success) { [System.Media.SystemSounds]::Exclamation.Play() }
        else         { [System.Media.SystemSounds]::Hand.Play() }
    } catch { }
    try {
        $h = (New-Object System.Windows.Interop.WindowInteropHelper($window)).Handle
        if ($h -ne [IntPtr]::Zero) { [GsFlash]::Flash($h) }
    } catch { }
}

# ---- Real .NET class for a disk row (required for WPF binding) --------
if (-not ('DiskRow' -as [type])) {
Add-Type -TypeDefinition @"
public class DiskRow {
    public int    Number   { get; set; }
    public string Model    { get; set; }
    public string Type      { get; set; }
    public string Bus { get; set; }
    public string Size    { get; set; }
    public string Serial     { get; set; }
    public long   SizeBytes   { get; set; }
    public string Health   { get; set; }
    public string Life     { get; set; }
    public string Hours     { get; set; }
    public string Temp   { get; set; }
}
"@
}

# ---- Hardware capability queries (read-only IOCTLs, allowed by Windows) --
if (-not ('GsQuery' -as [type])) {
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class GsQuery
{
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern SafeFileHandle CreateFile(string fn, uint acc, uint share, IntPtr sec,
                                            uint disp, uint flags, IntPtr tmpl);

    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool DeviceIoControl(SafeFileHandle h, uint code, IntPtr inBuf, int inSize,
                                       IntPtr outBuf, int outSize, out int ret, IntPtr ovl);

    const uint GENERIC_READ  = 0x80000000;
    const uint GENERIC_WRITE = 0x40000000;
    const uint SHARE_RW      = 0x3;
    const uint OPEN_EXISTING = 3;
    const uint IOCTL_STORAGE_QUERY_PROPERTY = 0x002D1400;
    const uint IOCTL_ATA_PASS_THROUGH       = 0x0004D02C;

    // NVMe Identify Controller (4096 bytes) - StorageAdapterProtocolSpecificProperty
    public static byte[] NvmeIdentify(int diskNo)
    {
        SafeFileHandle h = CreateFile(@"\\.\PhysicalDrive" + diskNo, GENERIC_READ, SHARE_RW,
                                      IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
        if (h.IsInvalid) return null;
        try {
            int spec = 28;                       // classic STORAGE_PROTOCOL_SPECIFIC_DATA
            int bufSize = 8 + spec + 4096 + 64;  // output: Version+Size + spec + data
            IntPtr buf = Marshal.AllocHGlobal(bufSize);
            try {
                Marshal.Copy(new byte[bufSize], 0, buf, bufSize);
                Marshal.WriteInt32(buf,  0, 49);   // StorageAdapterProtocolSpecificProperty
                Marshal.WriteInt32(buf,  4, 0);    // PropertyStandardQuery
                Marshal.WriteInt32(buf,  8, 3);    // ProtocolTypeNvme
                Marshal.WriteInt32(buf, 12, 1);    // NVMeDataTypeIdentify
                Marshal.WriteInt32(buf, 16, 1);    // CNS=1 (Identify Controller)
                Marshal.WriteInt32(buf, 20, 0);    // SubValue
                Marshal.WriteInt32(buf, 24, spec); // ProtocolDataOffset
                Marshal.WriteInt32(buf, 28, 4096); // ProtocolDataLength
                int ret;
                if (!DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY, buf, bufSize, buf, bufSize, out ret, IntPtr.Zero))
                    return null;
                int off = Marshal.ReadInt32(buf, 24);  // the offset the driver wrote back
                if (off < spec) off = spec;
                int start = 8 + off;
                if (ret < start + 512) return null;
                byte[] data = new byte[4096];
                Marshal.Copy(new IntPtr(buf.ToInt64() + start), data, 0, Math.Min(4096, ret - start));
                return data;
            } finally { Marshal.FreeHGlobal(buf); }
        } finally { h.Close(); }
    }

    // ATA IDENTIFY DEVICE (0xEC) - 512-byte word table
    public static byte[] AtaIdentify(int diskNo)
    {
        SafeFileHandle h = CreateFile(@"\\.\PhysicalDrive" + diskNo, GENERIC_READ | GENERIC_WRITE,
                                      SHARE_RW, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
        if (h.IsInvalid) return null;
        try {
            int ss = (IntPtr.Size == 8) ? 48 : 40;   // ATA_PASS_THROUGH_EX size (x64/x86)
            int total = ss + 512;
            IntPtr buf = Marshal.AllocHGlobal(total);
            try {
                Marshal.Copy(new byte[total], 0, buf, total);
                Marshal.WriteInt16(buf, 0, (short)ss);          // Length
                Marshal.WriteInt16(buf, 2, (short)0x03);        // ATA_FLAGS_DRDY_REQUIRED | DATA_IN
                Marshal.WriteInt32(buf, 8, 512);                // DataTransferLength
                Marshal.WriteInt32(buf, 12, 5);                 // TimeOut (seconds)
                int dbo = (IntPtr.Size == 8) ? 24 : 20;         // DataBufferOffset field
                if (IntPtr.Size == 8) Marshal.WriteInt64(buf, dbo, ss);
                else                  Marshal.WriteInt32(buf, dbo, ss);
                Marshal.WriteByte(buf, ss - 8 + 6, 0xEC);       // CurrentTaskFile[6] = IDENTIFY
                int ret;
                bool ok = DeviceIoControl(h, IOCTL_ATA_PASS_THROUGH, buf, total, buf, total, out ret, IntPtr.Zero);
                if (!ok || ret < total) return null;
                byte[] data = new byte[512];
                Marshal.Copy(new IntPtr(buf.ToInt64() + ss), data, 0, 512);
                bool empty = true;
                for (int i = 0; i < 512; i++) if (data[i] != 0) { empty = false; break; }
                return empty ? null : data;
            } finally { Marshal.FreeHGlobal(buf); }
        } finally { h.Close(); }
    }

    // Return the raw LBA count via an ATA command (48-bit preferred). In HPA/DCO detection
    // it is used for the "true physical" size. cmd48/cmd28: the opcode to use.
    static long AtaMaxLba(SafeFileHandle h, byte cmd48, byte cmd28)
    {
        int ss = (IntPtr.Size == 8) ? 48 : 40;
        int total = ss + 512;
        IntPtr buf = Marshal.AllocHGlobal(total);
        try {
            Marshal.Copy(new byte[total], 0, buf, total);
            Marshal.WriteInt16(buf, 0, (short)ss);       // Length
            // READ NATIVE MAX ADDRESS does NOT transfer data; the result is returned in the
            // LBA registers. So DATA_IN (0x02) is NOT needed, only DRDY_REQUIRED (0x01).
            // (A previous version wrongly passed 0x02, so the command was rejected on most
            //  drives and the feature was silently disabled.)
            Marshal.WriteInt16(buf, 2, (short)0x01);     // ATA_FLAGS_DRDY_REQUIRED
            Marshal.WriteInt32(buf, 8, 0);               // DataTransferLength = 0
            Marshal.WriteInt32(buf, 12, 5);              // TimeOut
            // for 48-bit commands the 48-bit flag (0x08) is added to AtaFlags
            int tfOff = ss - 8;                          // CurrentTaskFile[8]
            if (cmd48 != 0) {
                short fl = (short)(0x01 | 0x08);         // DRDY_REQUIRED | 48BIT_COMMAND
                Marshal.WriteInt16(buf, 2, fl);
                Marshal.WriteByte(buf, tfOff + 6, cmd48);   // Command
            } else {
                Marshal.WriteByte(buf, tfOff + 6, cmd28);
            }
            int ret;
            bool ok = DeviceIoControl(h, IOCTL_ATA_PASS_THROUGH, buf, total, buf, total, out ret, IntPtr.Zero);
            if (!ok) return -1;
            // Returned TaskFile: LBA bytes 3(low),4,5(mid/high) + in the prev registers
            // for 48-bit, PreviousTaskFile[3..5] are the high bytes; buffer layout ATA_PASS_THROUGH_EX
            // CurrentTaskFile[8]: [0]=err/feat [1]=count [2]=lbaLow [3]=lbaMid [4]=lbaHigh [5]=device [6]=cmd/status ...
            byte lbaLow  = Marshal.ReadByte(buf, tfOff + 2);
            byte lbaMid  = Marshal.ReadByte(buf, tfOff + 3);
            byte lbaHigh = Marshal.ReadByte(buf, tfOff + 4);
            long lba = (long)lbaLow | ((long)lbaMid << 8) | ((long)lbaHigh << 16);
            if (cmd48 != 0) {
                // 48-bit: the high bytes are in the PreviousTaskFile[8] block (not tfOff - 8,
                // in ATA_PASS_THROUGH_EX, Previous comes right before Current)
                int pOff = tfOff - 8;
                byte pLow  = Marshal.ReadByte(buf, pOff + 2);
                byte pMid  = Marshal.ReadByte(buf, pOff + 3);
                byte pHigh = Marshal.ReadByte(buf, pOff + 4);
                lba |= ((long)pLow << 24) | ((long)pMid << 32) | ((long)pHigh << 40);
            }
            return lba;      // MAX addressable LBA (address of the last sector)
        } finally { Marshal.FreeHGlobal(buf); }
    }

    // The disk's true physical sector count (even if HPA/DCO hides it).
    // Array: [0]=native sector count (-1 on failure), [1]=user sector count from IDENTIFY.
    public static long[] NativeSectors(int diskNo)
    {
        SafeFileHandle h = CreateFile(@"\\.\PhysicalDrive" + diskNo, GENERIC_READ | GENERIC_WRITE,
                                      SHARE_RW, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
        long nativeCount = -1, userCount = -1;
        if (h.IsInvalid) return new long[] { -1, -1 };
        try {
            // READ NATIVE MAX ADDRESS EXT (0x27) -> 48-bit; otherwise READ NATIVE MAX (0xF8)
            long maxLba = AtaMaxLba(h, 0x27, 0x00);
            if (maxLba < 0) maxLba = AtaMaxLba(h, 0x00, 0xF8);
            if (maxLba > 0) nativeCount = maxLba + 1;   // address -> count
        } catch { }
        h.Close();
        // user-visible sector count from IDENTIFY (words 100-103, 48-bit)
        byte[] id = AtaIdentify(diskNo);
        if (id != null) {
            long u = (long)BitConverter.ToUInt16(id, 200)
                   | ((long)BitConverter.ToUInt16(id, 202) << 16)
                   | ((long)BitConverter.ToUInt16(id, 204) << 32)
                   | ((long)BitConverter.ToUInt16(id, 206) << 48);
            if (u <= 0) u = BitConverter.ToUInt32(id, 120);   // word 60-61 (28-bit)
            userCount = u;
        }
        return new long[] { nativeCount, userCount };
    }
}
"@
}

# ============================ MAIN WINDOW (XAML) ============================
$xamlTemplate = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="{T:window_title}"
        Width="1050" Height="760" MinWidth="900" MinHeight="640"
        WindowStartupLocation="CenterScreen" Background="%BG%">
  <Window.Resources>
    <Style TargetType="Button">
      <Setter Property="Foreground" Value="White"/>
      <Setter Property="Background" Value="%PANEL2%"/>
      <Setter Property="BorderBrush" Value="%BORDER%"/>
      <Setter Property="Padding" Value="14,7"/>
      <Setter Property="FontSize" Value="13"/>
      <Setter Property="Cursor" Value="Hand"/>
    </Style>
    <Style TargetType="TextBlock">
      <Setter Property="Foreground" Value="%FG2%"/>
    </Style>
    <Style TargetType="CheckBox">
      <Setter Property="Foreground" Value="%FG2%"/>
      <Setter Property="Margin" Value="0,4,0,0"/>
    </Style>
    <!-- Disk list rows: selection/hover colors come from the theme; the system
         accent color would otherwise cause an unreadable "light gray on white" -->
    <Style TargetType="ListViewItem">
      <Setter Property="Foreground" Value="%FG%"/>
      <Setter Property="Background" Value="Transparent"/>
      <Setter Property="HorizontalContentAlignment" Value="Stretch"/>
      <Setter Property="VerticalContentAlignment" Value="Center"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ListViewItem">
            <Border Name="Bd" Background="{TemplateBinding Background}"
                    BorderThickness="0" Padding="2,3" SnapsToDevicePixels="True">
              <GridViewRowPresenter Content="{TemplateBinding Content}"
                                    Columns="{TemplateBinding GridView.ColumnCollection}"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="Bd" Property="Background" Value="%PANEL2%"/>
              </Trigger>
              <Trigger Property="IsSelected" Value="True">
                <Setter TargetName="Bd" Property="Background" Value="%BAR%"/>
                <Setter Property="Foreground" Value="#FFFFFFFF"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style TargetType="GridViewColumnHeader">
      <Setter Property="Foreground" Value="%FG2%"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="GridViewColumnHeader">
            <Border Background="%PANEL2%" BorderBrush="%BORDER%" BorderThickness="0,0,1,1" Padding="6,4">
              <TextBlock Text="{TemplateBinding Content}" Foreground="%FG2%"
                         FontWeight="SemiBold" TextTrimming="CharacterEllipsis"/>
            </Border>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
  </Window.Resources>

  <Grid Margin="16,12">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*" MinHeight="90"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="0.6*" MinHeight="48"/>
    </Grid.RowDefinitions>

    <!-- Title -->
    <Grid Grid.Row="0" Margin="0,0,0,10">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="*"/>
        <ColumnDefinition Width="Auto"/>
      </Grid.ColumnDefinitions>
      <StackPanel Orientation="Horizontal">
        <TextBlock Text="&#128737;" FontSize="26" Margin="0,0,10,0"/>
        <StackPanel>
          <TextBlock Text="Strix Disk Cleaner" FontSize="22" FontWeight="Bold" Foreground="%ACCENT%"/>
          <TextBlock Name="txtSubTitle" Text="{T:sub_title}" FontSize="12" Foreground="%SUB%"/>
        </StackPanel>
      </StackPanel>
      <StackPanel Grid.Column="1" Orientation="Horizontal" VerticalAlignment="Center">
        <TextBlock Name="lblLanguage" Text="{T:lbl_language}" VerticalAlignment="Center" Margin="0,0,6,0" FontSize="12"/>
        <ComboBox Name="cmbLanguage" Width="130" FontSize="12" Margin="0,0,14,0"/>
        <TextBlock Name="lblTheme" Text="{T:lbl_theme}" VerticalAlignment="Center" Margin="0,0,6,0" FontSize="12"/>
        <ComboBox Name="cmbTheme" Width="86" FontSize="12">
          <ComboBoxItem>{T:theme_dark}</ComboBoxItem>
          <ComboBoxItem>{T:theme_light}</ComboBoxItem>
        </ComboBox>
      </StackPanel>
    </Grid>

    <!-- Disk list -->
    <ListView Grid.Row="1" Name="lstDisks" Background="%PANEL%" Foreground="%FG%"
              BorderBrush="%BORDER%" FontSize="13" SelectionMode="Extended">
      <ListView.View>
        <GridView>
          <GridViewColumn Header="{T:col_disk}" Width="45"  DisplayMemberBinding="{Binding Number}"/>
          <GridViewColumn Header="{T:col_model}" Width="225" DisplayMemberBinding="{Binding Model}"/>
          <GridViewColumn Header="{T:col_type}" Width="60"  DisplayMemberBinding="{Binding Type}"/>
          <GridViewColumn Header="{T:col_bus}" Width="75" DisplayMemberBinding="{Binding Bus}"/>
          <GridViewColumn Header="{T:col_size}" Width="85" DisplayMemberBinding="{Binding Size}"/>
          <GridViewColumn Header="{T:col_serial}" Width="145" DisplayMemberBinding="{Binding Serial}"/>
          <GridViewColumn Header="{T:col_health}" Width="85" DisplayMemberBinding="{Binding Health}"/>
          <GridViewColumn Header="{T:col_life}" Width="70" DisplayMemberBinding="{Binding Life}"/>
          <GridViewColumn Header="{T:col_hours}" Width="90" DisplayMemberBinding="{Binding Hours}"/>
          <GridViewColumn Header="{T:col_temp}" Width="55" DisplayMemberBinding="{Binding Temp}"/>
        </GridView>
      </ListView.View>
    </ListView>

    <!-- Disk capability detection and recommendation panel -->
    <Border Grid.Row="2" Name="pnlSsdWarning" Background="%WARNBG%" BorderBrush="%WARNFG%"
            BorderThickness="1" CornerRadius="4" Padding="10" Margin="0,8,0,0" Visibility="Collapsed">
      <StackPanel>
        <ScrollViewer MaxHeight="110" VerticalScrollBarVisibility="Auto"
                      HorizontalScrollBarVisibility="Disabled">
          <TextBlock Name="txtSsdWarning" TextWrapping="Wrap" Foreground="%WARNFG%" FontSize="12"/>
        </ScrollViewer>
        <StackPanel Orientation="Horizontal" Margin="0,8,0,0">
          <Button Name="btnUefi" Content="{T:btn_uefi}"
                  HorizontalAlignment="Left" Padding="10,5" FontSize="12"
                  Visibility="Collapsed"/>
          <Button Name="btnSmart" Content="{T:smart_btn}"
                  HorizontalAlignment="Left" Margin="8,0,0,0" Padding="10,5" FontSize="12"/>
        </StackPanel>
      </StackPanel>
    </Border>

    <!-- Options -->
    <Grid Grid.Row="3" Margin="0,8,0,0">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="*"/>
        <ColumnDefinition Width="Auto"/>
      </Grid.ColumnDefinitions>
      <StackPanel Grid.Column="0">
        <TextBlock Name="lblMethod" Text="{T:lbl_method}" FontWeight="Bold" Margin="0,0,0,4"/>
        <ComboBox Name="cmbMethod" Width="520" HorizontalAlignment="Left" FontSize="13">
          <ComboBoxItem IsSelected="True">{T:y0}</ComboBoxItem>
          <ComboBoxItem>{T:y1}</ComboBoxItem>
          <ComboBoxItem>{T:y2}</ComboBoxItem>
          <ComboBoxItem>{T:y3}</ComboBoxItem>
        </ComboBox>
        <CheckBox Name="chkVerify" IsChecked="True" Content="{T:chk_verify}"/>
        <CheckBox Name="chkFormat" IsChecked="True" Content="{T:chk_format}"/>
        <CheckBox Name="chkReport" IsChecked="True" Content="{T:chk_report}"/>
        <CheckBox Name="chkPdf" IsChecked="True" Content="{T:chk_pdf}"/>
        <CheckBox Name="chkEject" IsChecked="True" Content="{T:chk_eject}"/>
        <CheckBox Name="chkTask" IsChecked="True" Content="{T:chk_task}"/>
        <CheckBox Name="chkSound" IsChecked="True" Content="{T:chk_sound}"/>
        <StackPanel Orientation="Horizontal" Margin="0,6,0,0">
          <TextBlock Name="lblReportFolder" Text="{T:lbl_report_folder}" VerticalAlignment="Center" FontSize="12"/>
          <TextBlock Name="txtReportFolder" Text="" VerticalAlignment="Center" Margin="6,0,6,0"
                     FontSize="12" Foreground="%SUB%" TextTrimming="CharacterEllipsis" MaxWidth="360"/>
          <Button Name="btnReportFolder" Content="{T:btn_report_folder}" Padding="8,3" FontSize="12"/>
        </StackPanel>
      </StackPanel>
      <StackPanel Grid.Column="1" VerticalAlignment="Bottom">
        <Grid Margin="0,0,0,8">
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="8"/>
            <ColumnDefinition Width="*"/>
          </Grid.ColumnDefinitions>
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="8"/>
            <RowDefinition Height="Auto"/>
          </Grid.RowDefinitions>
          <Button Name="btnRefresh" Content="{T:btn_refresh}"/>
          <Button Name="btnSpeed" Grid.Column="2" Content="{T:btn_speed}"/>
          <Button Name="btnTrace" Grid.Row="2" Content="{T:btn_trace}"/>
          <Button Name="btnSurface" Grid.Row="2" Grid.Column="2" Content="{T:btn_surface}"/>
        </Grid>
        <Button Name="btnWipe" Content="{T:btn_wipe}" Background="%RED%" FontWeight="Bold" FontSize="15" Padding="20,10"/>
        <Button Name="btnCancel" Content="{T:btn_cancel}" Margin="0,8,0,0" IsEnabled="False"/>
      </StackPanel>
    </Grid>

    <!-- Progress -->
    <StackPanel Grid.Row="4" Margin="0,8,0,0">
      <Grid>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>
        <TextBlock Name="txtStatus" Text="{T:status_ready}" FontSize="13" FontWeight="Bold" Foreground="%OK%"/>
        <TextBlock Grid.Column="1" Name="txtPass" Text="" FontSize="12" Foreground="%ACCENT%"/>
      </Grid>
      <ProgressBar Name="prgProgress" Height="22" Minimum="0" Maximum="100" Margin="0,6,0,4"
                   Background="%PANEL%" Foreground="%BAR%" BorderBrush="%BORDER%"/>
      <Grid>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="*"/>
        </Grid.ColumnDefinitions>
        <TextBlock Name="txtPercent" Text="" FontSize="12"/>
        <TextBlock Grid.Column="1" Name="txtSpeed" Text="" FontSize="12" HorizontalAlignment="Center"/>
        <TextBlock Grid.Column="2" Name="txtRemain" Text="" FontSize="12" HorizontalAlignment="Right"/>
      </Grid>
      <StackPanel Orientation="Horizontal" Margin="0,4,0,0">
        <TextBlock Name="txtTemp" Text="" FontSize="12" Foreground="%ACCENT%" VerticalAlignment="Center"/>
        <Border Name="brdTemp" BorderBrush="%BORDER%" BorderThickness="1" Margin="10,0,0,0" Visibility="Collapsed">
          <Canvas Name="cnvTemp" Width="260" Height="30" Background="%LOGBG%">
            <Polyline Name="plTemp" Stroke="%ACCENT%" StrokeThickness="1.5"/>
          </Canvas>
        </Border>
      </StackPanel>
    </StackPanel>

    <!-- Record -->
    <TextBox Grid.Row="5" Name="txtRecord" Margin="0,8,0,0" IsReadOnly="True"
             Background="%LOGBG%" Foreground="%SUB%" BorderBrush="%BORDER%"
             FontFamily="Consolas" FontSize="12" VerticalScrollBarVisibility="Auto" TextWrapping="Wrap"/>
  </Grid>
</Window>
'@

$xaml = Expand-Xaml $xamlTemplate
$reader = New-Object System.Xml.XmlNodeReader $xaml
$window = [Windows.Markup.XamlReader]::Load($reader)

# Window/taskbar icon: multi-size .ico embedded in the script
$script:AppIcon = $null
try {
    $iconBytes = [Convert]::FromBase64String($script:IconB64)
    $iconStream = New-Object System.IO.MemoryStream(,$iconBytes)
    $iconDecode  = New-Object System.Windows.Media.Imaging.IconBitmapDecoder(
        $iconStream,
        [System.Windows.Media.Imaging.BitmapCreateOptions]::PreservePixelFormat,
        [System.Windows.Media.Imaging.BitmapCacheOption]::OnLoad)
    $script:AppIcon = $iconDecode.Frames | Sort-Object PixelWidth -Descending | Select-Object -First 1
    if ($script:AppIcon) { $window.Icon = $script:AppIcon }
} catch { }

# Fit the window to the screen work area (small resolution / 125-150% DPI)
try {
    $ca = [System.Windows.SystemParameters]::WorkArea
    $window.MaxHeight = $ca.Height
    $window.MaxWidth  = $ca.Width
    if ($window.Height -gt $ca.Height - 4) { $window.Height = [Math]::Max(640, $ca.Height - 4) }
    if ($window.Width  -gt $ca.Width  - 4) { $window.Width  = [Math]::Max(900, $ca.Width  - 4) }
} catch { }

$lstDisks     = $window.FindName('lstDisks')
$cmbMethod      = $window.FindName('cmbMethod')
$chkVerify     = $window.FindName('chkVerify')
$chkFormat = $window.FindName('chkFormat')
$chkReport       = $window.FindName('chkReport')
$btnRefresh      = $window.FindName('btnRefresh')
$btnWipe         = $window.FindName('btnWipe')
$btnCancel       = $window.FindName('btnCancel')
$prgProgress    = $window.FindName('prgProgress')
$txtStatus       = $window.FindName('txtStatus')
$txtPass       = $window.FindName('txtPass')
$txtPercent       = $window.FindName('txtPercent')
$txtSpeed         = $window.FindName('txtSpeed')
$txtRemain       = $window.FindName('txtRemain')
$txtLog       = $window.FindName('txtRecord')
$pnlSsdWarn    = $window.FindName('pnlSsdWarning')
$txtSsdWarn    = $window.FindName('txtSsdWarning')
$btnUefi        = $window.FindName('btnUefi')
$btnSpeed         = $window.FindName('btnSpeed')
$btnTrace          = $window.FindName('btnTrace')
$btnSurface       = $window.FindName('btnSurface')
$chkPdf         = $window.FindName('chkPdf')
$chkSound         = $window.FindName('chkSound')
$cmbTheme        = $window.FindName('cmbTheme')
$cmbLanguage     = $window.FindName('cmbLanguage')
$lblLanguage     = $window.FindName('lblLanguage')
$lblTheme        = $window.FindName('lblTheme')
$txtSubTitle     = $window.FindName('txtSubTitle')
$lblMethod       = $window.FindName('lblMethod')
$lblReportFolder = $window.FindName('lblReportFolder')
$txtTemp         = $window.FindName('txtTemp')
$brdTemp         = $window.FindName('brdTemp')
$plTemp          = $window.FindName('plTemp')
$btnSmart       = $window.FindName('btnSmart')
$chkEject       = $window.FindName('chkEject')
$chkTaskbar       = $window.FindName('chkTask')
$txtReportFolder = $window.FindName('txtReportFolder')
$btnReportFolder = $window.FindName('btnReportFolder')
$tbItem         = $window.FindName('tbItem')
# The taskbar progress object is created in code (no XAML load risk).
# TaskbarItemInfo cannot always bind via x:Name from XAML, so this path is preferred.
if ($null -eq $tbItem) {
    try {
        $tbItem = New-Object System.Windows.Shell.TaskbarItemInfo
        $window.TaskbarItemInfo = $tbItem
    } catch { $tbItem = $null }
}

# ---- Live re-translation: re-apply every visible label from the active language ----
# Called once after the window loads and again whenever the language is changed, so
# the UI switches language without a restart. Only static chrome is set here; dynamic
# log lines and per-disk panels refresh in the new language on the next interaction.
function Update-UiText {
    try {
        $window.Title = (T 'window_title')
        if ($txtSubTitle)     { $txtSubTitle.Text     = (T 'sub_title') }
        if ($lblTheme)        { $lblTheme.Text        = (T 'lbl_theme') }
        if ($lblLanguage)     { $lblLanguage.Text     = (T 'lbl_language') }
        if ($lblMethod)       { $lblMethod.Text       = (T 'lbl_method') }
        if ($lblReportFolder) { $lblReportFolder.Text = (T 'lbl_report_folder') }
        if ($cmbTheme -and $cmbTheme.Items.Count -ge 2) {
            $cmbTheme.Items[0].Content = (T 'theme_dark')
            $cmbTheme.Items[1].Content = (T 'theme_light')
        }
        if ($cmbMethod -and $cmbMethod.Items.Count -ge 4) {
            $cmbMethod.Items[0].Content = (T 'y0')
            $cmbMethod.Items[1].Content = (T 'y1')
            $cmbMethod.Items[2].Content = (T 'y2')
            $cmbMethod.Items[3].Content = (T 'y3')
        }
        if ($btnUefi)         { $btnUefi.Content         = (T 'btn_uefi') }
        if ($btnSmart)        { $btnSmart.Content        = (T 'smart_btn') }
        if ($btnReportFolder) { $btnReportFolder.Content = (T 'btn_report_folder') }
        if ($btnRefresh)      { $btnRefresh.Content      = (T 'btn_refresh') }
        if ($btnSpeed)        { $btnSpeed.Content        = (T 'btn_speed') }
        if ($btnTrace)        { $btnTrace.Content        = (T 'btn_trace') }
        if ($btnSurface)      { $btnSurface.Content      = (T 'btn_surface') }
        if ($btnWipe)         { $btnWipe.Content         = (T 'btn_wipe') }
        if ($btnCancel)       { $btnCancel.Content       = (T 'btn_cancel') }
        if ($chkVerify)       { $chkVerify.Content       = (T 'chk_verify') }
        if ($chkFormat)       { $chkFormat.Content       = (T 'chk_format') }
        if ($chkReport)       { $chkReport.Content       = (T 'chk_report') }
        if ($chkPdf)          { $chkPdf.Content          = (T 'chk_pdf') }
        if ($chkEject)        { $chkEject.Content        = (T 'chk_eject') }
        if ($chkTaskbar)      { $chkTaskbar.Content      = (T 'chk_task') }
        if ($chkSound)        { $chkSound.Content        = (T 'chk_sound') }
        # Disk-list column headers (order matches the GridView column definitions)
        if ($lstDisks -and $lstDisks.View -and $lstDisks.View.Columns) {
            $cols = $lstDisks.View.Columns
            $hk = @('col_disk','col_model','col_type','col_bus','col_size','col_serial','col_health','col_life','col_hours','col_temp')
            for ($i = 0; $i -lt $cols.Count -and $i -lt $hk.Count; $i++) { $cols[$i].Header = (T $hk[$i]) }
        }
        # Idle status line only (language changes are blocked while an operation runs)
        if ($txtStatus -and ($null -eq $script:sync)) { $txtStatus.Text = (T 'status_ready') }
    } catch { }
}

# ============================ HELPER FUNCTIONS =========================
function Format-Size([long]$b) {
    if ($b -ge 1TB) { return ('{0:N2} TB' -f ($b / 1TB)) }
    if ($b -ge 1GB) { return ('{0:N1} GB' -f ($b / 1GB)) }
    if ($b -ge 1MB) { return ('{0:N0} MB' -f ($b / 1MB)) }
    return "$b B"
}

function Add-LogEntry([string]$message) {
    $txtLog.AppendText(('[{0}] {1}' -f (Get-Date -Format 'HH:mm:ss'), $message) + [Environment]::NewLine)
    $txtLog.ScrollToEnd()
}

# ---- Report folder: from settings; falls back to the desktop ---------------
function Get-ReportFolder {
    $k = "$($script:Settings.ReportFolder)".Trim()
    if ($k -and (Test-Path $k -PathType Container)) { return $k }
    return [Environment]::GetFolderPath('Desktop')
}

# ---- HPA/DCO (hidden area) detection ------------------------------------------
# Returns: @{ Present=$bool; HiddenBytes=[long]; NativeSector; UserSector; Queryable=$bool }
$script:hiddenCache = @{}
function Get-HiddenArea([int]$n, [string]$bus) {
    if ($script:hiddenCache.ContainsKey($n)) { return $script:hiddenCache[$n] }
    $r = @{ Present=$false; HiddenBytes=0L; NativeSector=$null; UserSector=$null; Queryable=$false }
    # A USB bridge usually blocks ATA commands; we try to query and flag it if not
    try {
        $s = [GsQuery]::NativeSectors($n)
        $native = [long]$s[0]; $user = [long]$s[1]
        if ($native -gt 0 -and $user -gt 0) {
            $r.Queryable = $true
            $r.NativeSector = $native; $r.UserSector = $user
            if ($native -gt $user) {
                $r.Present = $true
                $r.HiddenBytes = ($native - $user) * 512L
            }
        }
    } catch { }
    $script:hiddenCache[$n] = $r
    return $r
}

# ---- Disk partition / used-space preview (read-only) -----------------------
function Get-PreviewText([int]$n) {
    $sb = New-Object System.Text.StringBuilder
    $partitionCount = 0; $totalUsed = 0L; $seen = $false
    try {
        $partitions = @(Get-Partition -DiskNumber $n -ErrorAction SilentlyContinue |
                      Where-Object { $_.Type -ne 'Reserved' })
        foreach ($p in $partitions) {
            $partitionCount++
            if ($p.DriveLetter) {
                $seen = $true
                try {
                    $v = Get-Volume -DriveLetter $p.DriveLetter -ErrorAction Stop
                    $total = [long]$v.Size; $freeSpace = [long]$v.SizeRemaining
                    $used = [Math]::Max(0L, $total - $freeSpace); $totalUsed += $used
                    $pct = if ($total -gt 0) { [int](($used * 100) / $total) } else { 0 }
                    $fs = if ($v.FileSystem) { "$($v.FileSystem)" } else { 'RAW' }
                    $labelSuffix = if ($v.FileSystemLabel) { " '$($v.FileSystemLabel)'" } else { '' }
                    [void]$sb.AppendLine(((T 'preview_partition') -f `
                        $p.DriveLetter, ($fs + $labelSuffix), (Format-Size $used), (Format-Size $total), $pct, (Format-Size $freeSpace)))
                } catch {
                    [void]$sb.AppendLine(((T 'preview_partition_noletter') -f $partitionCount, (Format-Size ([long]$p.Size))))
                }
            } else {
                [void]$sb.AppendLine(((T 'preview_partition_noletter') -f $partitionCount, (Format-Size ([long]$p.Size))))
            }
        }
    } catch { }
    if ($partitionCount -eq 0) { return (T 'preview_empty') }
    $summary = (T 'preview_summary') -f $partitionCount, (Format-Size $totalUsed)
    return ($sb.ToString().TrimEnd() + "`n" + $summary)
}

# ---- Safely eject a USB disk -----------------------------------------------
function Eject-Disk([int]$n) {
    try {
        $dd = Get-CimInstance Win32_DiskDrive -Filter "Index=$n" -ErrorAction Stop
        if (-not $dd) { return }
        # Safely eject the attached volumes via the Shell 'Eject' verb.
        # The COM object is created once and released at the end.
        $sh = $null
        try {
            $sh = New-Object -ComObject Shell.Application
            Get-Partition -DiskNumber $n -ErrorAction SilentlyContinue |
                Where-Object DriveLetter |
                ForEach-Object {
                    $vol = "$($_.DriveLetter):"
                    $ns = $sh.Namespace(17)
                    if ($ns) {
                        $item = $ns.ParseName($vol)
                        if ($item) { $item.InvokeVerb('Eject') }
                    }
                }
        } catch { }
        finally {
            if ($sh) { try { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($sh) } catch { } }
        }
        Add-LogEntry ((T 'eject_ok') -f $n)
    } catch {
        Add-LogEntry ((T 'eject_error') -f $_.Exception.Message)
    }
}


# ---- Disk health / SMART query (v1.3) -----------------------------------
$script:healthCache = @{}
function Get-HealthInfo([int]$n) {
    if ($script:healthCache.ContainsKey($n)) { return $script:healthCache[$n] }
    $s = [pscustomobject]@{
        Status='-'; Wear=$null; PowerOnHours=$null; TempC=$null; TempMax=$null
        ReadErrors=$null; ReadUncorrectable=$null; WriteErrors=$null; WriteUncorrectable=$null
        Smart='-'; Detail=(New-Object System.Collections.Generic.List[string])
    }
    try {
        $pd = Get-PhysicalDisk -DeviceNumber $n -ErrorAction Stop
        if ($pd) {
            $s.Status = switch ("$($pd.HealthStatus)") {
                'Healthy'   { T 's_healthy' }
                'Warning'   { T 's_warning' }
                'Unhealthy' { T 's_unhealthy' }
                default     { if ("$($pd.HealthStatus)") { "$($pd.HealthStatus)" } else { '-' } }
            }
            try {
                $rc = $pd | Get-StorageReliabilityCounter -ErrorAction Stop
                if ($rc) {
                    if ($null -ne $rc.Wear -and "$($rc.Wear)" -ne '')                 { $s.Wear = [int]$rc.Wear }
                    if ($null -ne $rc.PowerOnHours -and "$($rc.PowerOnHours)" -ne '') { $s.PowerOnHours  = [long]$rc.PowerOnHours }
                    if ($null -ne $rc.Temperature -and [int]$rc.Temperature -gt 0)    { $s.TempC = [int]$rc.Temperature }
                    if ($null -ne $rc.TemperatureMax -and [int]$rc.TemperatureMax -gt 0) { $s.TempMax = [int]$rc.TemperatureMax }
                    if ($null -ne $rc.ReadErrorsTotal)         { $s.ReadErrors         = [long]$rc.ReadErrorsTotal }
                    if ($null -ne $rc.ReadErrorsUncorrected)   { $s.ReadUncorrectable = [long]$rc.ReadErrorsUncorrected }
                    if ($null -ne $rc.WriteErrorsTotal)        { $s.WriteErrors         = [long]$rc.WriteErrorsTotal }
                    if ($null -ne $rc.WriteErrorsUncorrected)  { $s.WriteUncorrectable = [long]$rc.WriteErrorsUncorrected }
                }
            } catch { $s.Detail += (T 's_counter_none') }
            try {
                $dd = Get-CimInstance Win32_DiskDrive -Filter "Index=$n" -ErrorAction Stop
                $pnp = "$($dd.PNPDeviceID)".Trim()
                $fp = $null
                if ($pnp) {
                    $fp = Get-CimInstance -Namespace root\wmi -Class MSStorageDriver_FailurePredictStatus -ErrorAction Stop |
                          Where-Object { "$($_.InstanceName)" -like ($pnp + '*') } | Select-Object -First 1
                }
                if ($fp) { $s.Smart = if ($fp.PredictFailure) { T 's_smart_bad' } else { T 's_smart_good' } }
            } catch { }
        }
    } catch { $s.Detail += (T 's_query_none') }
    $script:healthCache[$n] = $s
    return $s
}

function Get-HealthSummary($sg, [string]$kind) {
    $p = New-Object System.Collections.Generic.List[string]
    $p.Add(((T 's_status') -f $sg.Status))
    if ($null -ne $sg.Wear) {
        $p.Add(((T 's_wear') -f $sg.Wear, (100 - $sg.Wear)))
    } elseif ($kind -eq 'SSD') { $p.Add((T 's_wear_none')) }
    if ($null -ne $sg.PowerOnHours) { $p.Add(((T 's_hours') -f $sg.PowerOnHours, [math]::Round($sg.PowerOnHours/24.0))) }
    if ($null -ne $sg.TempC) {
        $temp = (T 's_temp') -f $sg.TempC
        if ($null -ne $sg.TempMax) { $temp += ((T 's_temp_max') -f $sg.TempMax) }
        $p.Add($temp)
    }
    if ($null -ne $sg.ReadErrors -or $null -ne $sg.WriteErrors) {
        $p.Add(((T 's_errors') -f `
            $(if ($null -ne $sg.ReadErrors) { $sg.ReadErrors } else { '-' }),
            $(if ($null -ne $sg.ReadUncorrectable) { $sg.ReadUncorrectable } else { '-' }),
            $(if ($null -ne $sg.WriteErrors) { $sg.WriteErrors } else { '-' }),
            $(if ($null -ne $sg.WriteUncorrectable) { $sg.WriteUncorrectable } else { '-' })))
    }
    if ($sg.Smart -ne '-') { $p.Add(((T 's_smart') -f $sg.Smart)) }
    foreach ($d in $sg.Detail) { $p.Add($d) }
    return ($p -join ' | ')
}

function Update-DiskList {
    $script:healthCache = @{}
    $script:hiddenCache = @{}
    $lstDisks.ItemsSource = $null
    $rows = [System.Collections.ObjectModel.ObservableCollection[DiskRow]]::new()
    $physical = @{}
    try { Get-PhysicalDisk | ForEach-Object { $physical[[int]$_.DeviceId] = $_ } } catch { }

    $script:protection = Get-ProtectedDisks
    if ($script:protection.Failed) {
        # Fail closed: could not verify which disk is the system disk, so show
        # NOTHING as erasable rather than risk listing the system disk.
        Add-LogEntry "PROTECTION SHIELD: disk protection could not be verified - the disk list is hidden for safety. Reopen the app or check the Windows Storage service."
        $lstDisks.ItemsSource = $rows   # empty collection
        return
    }
    foreach ($d in (Get-Disk | Sort-Object Number)) {
        if ($script:protection.Numbers.ContainsKey([int]$d.Number)) {
            Add-LogEntry ("PROTECTION SHIELD: Disk {0} ({1}) hidden - {2}." -f $d.Number, "$($d.FriendlyName)".Trim(), $script:protection.Numbers[[int]$d.Number])
            continue
        }
        $pd = $physical[[int]$d.Number]
        $kind = 'Unknown'
        if ($pd) {
            switch ("$($pd.MediaType)") {
                'HDD'         { $kind = 'HDD' }
                'SSD'         { $kind = 'SSD' }
                'Unspecified' { $kind = if ($d.BusType -eq 'USB') { 'Flash' } else { 'Unknown' } }
                default       { $kind = "$($pd.MediaType)" }
            }
        } elseif ($d.BusType -eq 'USB') { $kind = 'Flash' }
        if ($d.BusType -eq 'NVMe') { $kind = 'SSD' }

        $s = New-Object DiskRow
        $s.Number   = [int]$d.Number
        $s.Model    = "$($d.FriendlyName)".Trim()
        $s.Type      = $kind
        $s.Bus = "$($d.BusType)"
        $s.Size    = Format-Size ([long]$d.Size)
        $s.Serial     = "$($d.SerialNumber)".Trim()
        $s.SizeBytes   = [long]$d.Size
        # v1.3: health columns
        $sg = Get-HealthInfo ([int]$d.Number)
        $s.Health = "$($sg.Status)"
        $s.Life   = if ($null -ne $sg.Wear)  { ('%{0}' -f (100 - $sg.Wear)) } else { '-' }
        $s.Hours   = if ($null -ne $sg.PowerOnHours)   { ('{0:N0}' -f $sg.PowerOnHours) } else { '-' }
        $s.Temp = if ($null -ne $sg.TempC) { ('{0} C' -f $sg.TempC) } else { '-' }
        $rows.Add($s)
    }
    $lstDisks.ItemsSource = $rows
    Add-LogEntry ("Disk list refreshed. {0} wipeable disk(s) found (the system disk is hidden for safety)." -f $rows.Count)
}

# ---- Method definitions ------------------------------------------------------
function Get-WipeMethod {
    switch ($cmbMethod.SelectedIndex) {
        0 { return @{ Name = 'NIST SP 800-88 Rev.1 (Clear) - single pass 0x00';              Passes = @('zero') } }
        1 { return @{ Name = 'Single pass cryptographic random data';                         Passes = @('random') } }
        2 { return @{ Name = 'DoD 5220.22-M - 3 passes (0x00, 0xFF, random)';                 Passes = @('zero','ones','random') } }
        3 { return @{ Name = 'Advanced 7 passes (0x00,0xFF,0x00,0xFF,0x00,0xFF,random)';      Passes = @('zero','ones','zero','ones','zero','ones','random') } }
    }
}

# ---- Hardware capability detection and recommendation engine (v1.1) ------------------------
$script:capabilityCache = @{}
$script:lastDetect = $null
$script:lastHealth = $null

# ---- PROTECTION SHIELD (v1.2): the system disk can never be targeted -------
function Get-ProtectedDisks {
    # Collects both the NUMBERS and SERIALS of the protected disks.
    # Serial tracking recognizes the system disk even if numbers change.
    $numbers = @{}
    $serials   = New-Object System.Collections.Generic.HashSet[string]
    $sysLetter = ($env:SystemDrive).TrimEnd(':')   # usually C

    # Pagefile-hosting disks (parity with the Linux swap guard): a SECONDARY data
    # disk holding an active pagefile must never be erased, or the running system
    # corrupts / BSODs. Map each pagefile's drive letter to its disk number.
    $pageDisks = New-Object System.Collections.Generic.HashSet[int]
    try {
        foreach ($pf in (Get-CimInstance Win32_PageFileUsage -ErrorAction Stop)) {
            $pl = "$($pf.Name)".TrimStart().Substring(0,1)   # 'C' from 'C:\pagefile.sys'
            foreach ($pp in @(Get-Partition -DriveLetter $pl -ErrorAction SilentlyContinue)) {
                [void]$pageDisks.Add([int]$pp.DiskNumber)
            }
        }
    } catch { }

    try {
        $disks = Get-Disk -ErrorAction Stop
    } catch {
        # FAIL CLOSED: if the disk list cannot be enumerated (WMI/Storage hiccup)
        # we must not declare anything erasable. Failed=$true => callers treat
        # EVERY disk as protected rather than showing the system disk as erasable.
        return @{ Numbers = $numbers; Serials = $serials; Failed = $true }
    }

    $failed = $false
    foreach ($d in $disks) {
        try {
            $reason = @()
            if ($d.IsBoot)   { $reason += 'boot disk of the running Windows' }
            if ($d.IsSystem) { $reason += 'hosts the system/EFI partition' }
            $letters = @(Get-Partition -DiskNumber $d.Number -ErrorAction SilentlyContinue |
                         ForEach-Object { "$($_.DriveLetter)" })
            if ($letters -contains $sysLetter)       { $reason += "carries the $env:SystemDrive drive" }
            if ($pageDisks.Contains([int]$d.Number)) { $reason += 'hosts an active pagefile' }
            if ($reason.Count -gt 0) {
                $numbers[[int]$d.Number] = ($reason -join '; ')
                $s = "$($d.SerialNumber)".Trim()
                if ($s) { [void]$serials.Add($s) }
            }
        } catch {
            # A per-disk query failed: fail closed for THIS disk (mark protected).
            $numbers[[int]$d.Number] = 'protection status could not be determined'
            $failed = $true
        }
    }
    return @{ Numbers = $numbers; Serials = $serials; Failed = $failed }
}
$script:protection = Get-ProtectedDisks

function Test-SafetyWall([int]$n, [string]$serial) {
    # Returns null = allowed. Returns text = BLOCKED (reason text).
    $k = Get-ProtectedDisks   # FRESH calc on every call - never trust a cache here
    $script:protection = $k
    if ($k.Failed) { return "Disk protection status could not be verified (disk enumeration failed) - refusing for safety" }
    if ($k.Numbers.ContainsKey($n)) { return "Disk $n is protected: $($k.Numbers[$n])" }
    $s = "$serial".Trim()
    if ($s -and $k.Serials.Contains($s)) { return "This disks serial number ($s) belongs to the protected system disk" }
    return $null
}


$script:OemName  = 'Unknown'
$script:OemPath = "check the BIOS/UEFI menu for a built-in Secure Erase style tool"
try {
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    $bb = Get-CimInstance Win32_BaseBoard -ErrorAction SilentlyContinue
    $u  = "$($cs.Manufacturer)".Trim()
    if ($u -match 'System manufacturer|To be filled|^$') { $u = "$($bb.Manufacturer)".Trim() }
    $script:OemName = $u
    switch -Regex ($u) {
        'ASUS'           { $script:OemPath = 'UEFI (Del) -> Advanced Mode (F7) -> Tool -> ASUS Secure Erase' }
        'Micro-Star|MSI' { $script:OemPath = 'BIOS (Del) -> Settings -> Advanced -> Secure Erase+' }
        'ASRock'         { $script:OemPath = 'UEFI (F2/Del) -> Tool -> SSD Secure Erase / NVMe Sanitize Tool' }
        'Gigabyte|GIGA'  { $script:OemPath = 'BIOS (Del) -> Settings (a Secure Erase entry exists on most models)' }
        'Dell'           { $script:OemPath = 'F2 at boot -> Maintenance -> Data Wipe' }
        'LENOVO'         { $script:OemPath = 'F1 at boot -> Security (Secure Wipe / Data Disposal depending on model)' }
        'HP|Hewlett'     { $script:OemPath = 'F10 at boot -> Security -> Secure Erase (model dependent)' }
    }
} catch { }

function Get-Capabilities([int]$n, [string]$bus, [string]$kind) {
    if ($script:capabilityCache.ContainsKey($n)) { return $script:capabilityCache[$n] }
    $y = @{ Nvme=$false; SaniCrypto=$false; SaniBlock=$false; SaniOver=$false; FmtCrypto=$false
            SecSR=$false; Ata=$false; AtaSec=$false; AtaEnh=$false; AtaFrozen=$false
            Tcg=$false; Trim=$false }
    try {
        if ($bus -eq 'NVMe' -or $kind -eq 'SSD') {
            $id = [GsQuery]::NvmeIdentify($n)
            if ($id) {
                $y.Nvme = $true; $y.Trim = $true
                $oacs = [BitConverter]::ToUInt16($id, 256)   # Optional Admin Cmd Support
                $sani = [BitConverter]::ToUInt32($id, 328)   # SANICAP
                $fna  = $id[524]                             # Format NVM Attributes
                $y.SecSR      = (($oacs -band 1)  -ne 0)     # Security Send/Recv -> possible Opal
                $y.SaniCrypto = (($sani -band 1)  -ne 0)
                $y.SaniBlock  = (($sani -band 2)  -ne 0)
                $y.SaniOver   = (($sani -band 4)  -ne 0)
                $y.FmtCrypto  = (($fna  -band 4)  -ne 0)     # Format SES=2 (crypto) support
            }
        }
        if (-not $y.Nvme) {
            $ata = [GsQuery]::AtaIdentify($n)
            if ($ata) {
                $y.Ata = $true
                $w48  = [BitConverter]::ToUInt16($ata, 96)    # Trusted Computing (TCG/Opal)
                $w128 = [BitConverter]::ToUInt16($ata, 256)   # Security status
                $w169 = [BitConverter]::ToUInt16($ata, 338)   # DSM/TRIM
                $y.Tcg       = (($w48  -band 1)  -ne 0)
                $y.AtaSec    = (($w128 -band 1)  -ne 0)
                $y.AtaFrozen = (($w128 -band 8)  -ne 0)
                $y.AtaEnh    = (($w128 -band 32) -ne 0)
                $y.Trim      = (($w169 -band 1)  -ne 0)
            }
        }
    } catch { }
    $script:capabilityCache[$n] = $y
    return $y
}

function New-Recommendation($row, $y) {
    $detect = New-Object System.Collections.Generic.List[string]
    $recommendation  = New-Object System.Collections.Generic.List[string]

    if ($row.Type -eq 'HDD') {
        $detect.Add('Magnetic disk (HDD)')
        if ($y.AtaSec) { $detect.Add('ATA Secure Erase supported' + $(if ($y.AtaEnh) {' (enhanced)'} else {''})) }
        $recommendation.Add('On an HDD, overwriting alone makes data unrecoverable (NIST 800-88); no extra hardware step is needed.')
    }
    elseif ($row.Type -eq 'Flash') {
        $detect.Add('USB flash drive - exposes no hardware secure-erase interface')
        $recommendation.Add('Overwriting is the STRONGEST method available for this medium; that is exactly what this app does.')
    }
    else {
        # SSD / NVMe
        if ($y.Nvme) {
            if ($y.SaniCrypto -or $y.SaniBlock -or $y.SaniOver) {
                $m = @(); if ($y.SaniCrypto) {$m += 'crypto'}; if ($y.SaniBlock) {$m += 'block'}; if ($y.SaniOver) {$m += 'overwrite'}
                $detect.Add('NVMe SANITIZE supported: ' + ($m -join ', '))
                $recommendation.Add('STRONGEST PATH (Purge): the nvme sanitize command from a Linux live USB (see README, Method 2).')
            }
            elseif ($y.FmtCrypto) {
                $detect.Add('NVMe Format crypto-erase (SES=2) supported')
                $recommendation.Add('For Purge: nvme format --ses=2 from a Linux live USB (see README, Method 2).')
            }
            else {
                $detect.Add('NVMe controller does not report Sanitize')
                $recommendation.Add('nvme format --ses=1 can be tried from a Linux live USB.')
            }
            if ($y.SecSR) {
                $detect.Add('Security Send/Receive present -> TCG Opal likely')
                $recommendation.Add('If the drive label shows a PSID code: sedutil-cli --PSIDrevert crypto-erases it in seconds (see README, Method 3).')
            }
        }
        elseif ($y.Ata) {
            if ($y.AtaSec) {
                $detect.Add('ATA Secure Erase supported' + $(if ($y.AtaEnh) {' (enhanced)'} else {''}) + $(if ($y.AtaFrozen) {' - currently FROZEN'} else {''}))
                $recommendation.Add('For Purge: hdparm Secure Erase from a Linux live USB (see README, Method 2).' + $(if ($y.AtaFrozen) {' FROZEN state: sleep and wake the computer first.'} else {''}))
            }
            if ($y.Tcg) {
                $detect.Add('TCG/Opal supported')
                $recommendation.Add('sedutil-cli PSIDrevert can be used with the PSID on the label (see README, Method 3).')
            }
            if (-not $y.AtaSec -and -not $y.Tcg) { $detect.Add('Drive reports no secure-erase capability') }
        }
        else {
            $detect.Add('Capability query returned no answer' + $(if ($row.Bus -eq 'USB') {' (USB enclosures/bridges usually block these queries)'} else {''}))
            $recommendation.Add('Overwrite + TRIM is the best that can be done over this connection.')
        }
        $recommendation.Add("On this computer ($script:OemName) the BIOS path is: $script:OemPath - the button below restarts straight into UEFI.")
    }

    $recommendation.Add('What this app provides: full visible-area overwrite + verification + automatic TRIM (when formatting is on) = NIST 800-88 Clear.')

    $panel = "CAPABILITY DETECTION - Disk $($row.Number)  [$($row.Type), $($row.Bus)]`n" +
             '  - ' + ($detect -join "`n  - ") + "`n`nRECOMMENDED PATH:`n" +
             '  - ' + ($recommendation -join "`n  - ")

    return @{ Summary = ($detect -join '; '); Recommendation = ($recommendation -join ' '); Panel = $panel }
}

# ============================ BACKGROUND WORKER ==============================
$workerScript = {
    param($sync)

    function WLog([string]$m) { [void]$sync.Record.Add(('[{0}] {1}' -f (Get-Date -Format 'HH:mm:ss'), $m)) }

    function Fill-Buffer([byte[]]$buf, [byte]$value) {
        $buf[0] = $value
        $len = 1
        while ($len -lt $buf.Length) {
            $copy = [Math]::Min($len, $buf.Length - $len)
            [Array]::Copy($buf, 0, $buf, $len, $copy)
            $len += $copy
        }
    }

    function Assert-DiskProtection([string]$stage) {
        # Runs right before each destructive step. Re-queries the disk in its
        # CURRENT state; validates identity even if numbers changed mid-session.
        $d = Get-Disk -Number $sync.DiskNo -ErrorAction Stop
        if ($d.IsBoot)   { throw ($sync.M.m_k_boot   -f $stage) }
        if ($d.IsSystem) { throw ($sync.M.m_k_system -f $stage) }
        $serial = "$($d.SerialNumber)".Trim()
        foreach ($ks in $sync.ProtectedSerials) {
            if ($ks -and $serial -eq $ks) { throw ($sync.M.m_k_serial_match -f $stage) }
        }
        if ($sync.ProtectedNumbers -contains [int]$d.Number) {
            throw ($sync.M.m_k_num -f $stage)
        }
        if ($sync.ExpectedSerial -and $serial -ne $sync.ExpectedSerial) {
            throw ($sync.M.m_k_serial_changed -f $stage, $sync.ExpectedSerial, $serial)
        }
        if ([long]$d.Size -ne [long]$sync.SizeBytes) {
            throw ($sync.M.m_k_size -f $stage, $sync.SizeBytes, $d.Size)
        }
        $sysLetter = "$($sync.SystemDrive)".TrimEnd(':')
        $sysPartition = Get-Partition -DiskNumber $sync.DiskNo -ErrorAction SilentlyContinue |
                    Where-Object { "$($_.DriveLetter)" -eq $sysLetter }
        if ($sysPartition) { throw ($sync.M.m_k_c -f $stage, $sync.SystemDrive) }
        # Live pagefile guard (parity with the Linux swap check): refuse even if a
        # pagefile was placed on this disk AFTER the protected set was snapshotted.
        $onPageDisk = $false
        try {
            foreach ($pf in (Get-CimInstance Win32_PageFileUsage -ErrorAction Stop)) {
                $pl = "$($pf.Name)".TrimStart().Substring(0,1)
                $pp = Get-Partition -DriveLetter $pl -ErrorAction SilentlyContinue
                if ($pp -and ([int]$pp.DiskNumber -eq [int]$d.Number)) { $onPageDisk = $true }
            }
        } catch { }
        if ($onPageDisk) { throw ($sync.M.m_k_num -f $stage) }
    }

    $online = $false
    $fs = $null; $handle = $null
    try {
        $n      = [int]$sync.DiskNo
        $size  = [long]$sync.SizeBytes
        $startTime = Get-Date

        WLog ($sync.M.m_op_started -f $n, $sync.Model, [math]::Round($size/1GB,1))
        WLog ($sync.M.m_method -f $sync.MethodName)

        Assert-DiskProtection 'start'
        WLog ($sync.M.m_protect_ok -f $sync.SystemDrive)

        # 1) Clear the partition table (diskpart 'clean' equivalent) -> volumes drop, raw writes are freed
        $sync.Status = $sync.M.m_status_partition
        Set-Disk  -Number $n -IsReadOnly $false -ErrorAction SilentlyContinue
        try { Clear-Disk -Number $n -RemoveData -RemoveOEM -Confirm:$false -ErrorAction Stop }
        catch { WLog ($sync.M.m_cleardisk_note -f $_.Exception.Message) }
        Start-Sleep -Milliseconds 800

        # 2) Take the disk offline if possible (USB flash does not support it, that is fine)
        try { Set-Disk -Number $n -IsOffline $true -ErrorAction Stop; $online = $true } catch { }

        # 3) Open raw disk access
        if (-not ('GsLocal' -as [type])) {
            Add-Type -TypeDefinition @"
using System;
using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
public static class GsLocal {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern SafeFileHandle CreateFile(string lpFileName, uint dwDesiredAccess,
        uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition,
        uint dwFlagsAndAttributes, IntPtr hTemplateFile);
}
"@
        }
        Assert-DiskProtection 'pre-raw-access'
        # Note: in Windows PowerShell 5.1 the 0xC0000000 hex constant parses as a negative Int32 (-1073741824)
        # and cannot bind to the 'uint dwDesiredAccess' parameter (the v1.2 bug).
        # So the GENERIC_READ|GENERIC_WRITE value is passed explicitly as UInt32.
        $ACCESS_READ_WRITE = [uint32]3221225472   # 0xC0000000 = GENERIC_READ | GENERIC_WRITE
        $handle = [GsLocal]::CreateFile("\\.\PHYSICALDRIVE$n", $ACCESS_READ_WRITE, [uint32]3, [IntPtr]::Zero, [uint32]3, [uint32]0, [IntPtr]::Zero)
        if ($handle.IsInvalid) {
            throw ($sync.M.m_raw_error -f [Runtime.InteropServices.Marshal]::GetLastWin32Error())
        }
        $fs = New-Object System.IO.FileStream($handle, [System.IO.FileAccess]::ReadWrite)

        $part = 4MB
        $buf   = New-Object byte[] $part
        # Modern cryptographic RNG (RNGCryptoServiceProvider is obsolete in .NET). IDisposable;
        # released in the finally block.
        $rng   = [System.Security.Cryptography.RandomNumberGenerator]::Create()

        # 4) Overwrite passes
        $passCount = $sync.Passes.Count
        $gIdx = 0
        foreach ($pattern in $sync.Passes) {
            $gIdx++
            $patternName = switch ($pattern) { 'zero' {'0x00'} 'ones' {'0xFF'} 'random' { $sync.M.m_random } }
            $sync.Pass = $sync.M.m_pass_fmt -f $gIdx, $passCount, $patternName
            $sync.Status = $sync.M.m_status_write
            WLog ($sync.M.m_pass_start -f $gIdx, $passCount, $patternName)

            switch ($pattern) {
                'zero' { Fill-Buffer $buf 0x00 }
                'ones'   { Fill-Buffer $buf 0xFF }
            }

            $fs.Position = 0
            [long]$writtenBytes = 0
            while ($writtenBytes -lt $size) {
                if ($sync.Cancel) { throw '__CANCEL__' }
                # [long] cast is required: otherwise PowerShell picks the Min(int,int) overload and
                # cannot convert the remaining byte count (larger than Int32), raising "val2 ... Int32".
                $count = [int][Math]::Min([long]$part, [long]($size - $writtenBytes))
                if ($pattern -eq 'random') { $rng.GetBytes($buf) }
                $fs.Write($buf, 0, $count)
                $writtenBytes += $count
                $sync.DoneBytes = $sync.BaseBytes + $writtenBytes
            }
            $fs.Flush($true)
            $sync.BaseBytes += $size
            WLog ($sync.M.m_pass_done -f $gIdx, $passCount)
        }

        # 5) Verification
        $verifyResult = $sync.M.m_notdone
        if ($sync.Verify) {
            $sync.Status = $sync.M.m_status_verify
            $sync.Pass = $sync.M.m_verification_label
            $lastPattern = $sync.Passes[$sync.Passes.Count - 1]
            $expected = $null
            if ($lastPattern -eq 'zero') { $expected = [byte]0x00 }
            if ($lastPattern -eq 'ones')   { $expected = [byte]0xFF }

            $readBuf  = New-Object byte[] 65536
            $random = New-Object System.Random
            $offsets = New-Object System.Collections.Generic.List[long]
            $offsets.Add(0)
            if ($size -gt 131072) { $offsets.Add($size - 65536) }
            for ($i = 0; $i -lt 256; $i++) {
                $o = [long]($random.NextDouble() * ($size - 65536))
                $offsets.Add($o - ($o % 4096))
            }

            $badBlock = 0
            foreach ($o in $offsets) {
                if ($sync.Cancel) { throw '__CANCEL__' }
                $fs.Position = $o
                $readBytes = $fs.Read($readBuf, 0, $readBuf.Length)
                if ($null -ne $expected) {
                    for ($j = 0; $j -lt $readBytes; $j++) {
                        if ($readBuf[$j] -ne $expected) { $badBlock++; break }
                    }
                }
            }
            if ($badBlock -gt 0) { throw ($sync.M.m_dv_fail -f $badBlock) }
            $verifyResult = if ($null -ne $expected) {
                $sync.M.m_dv_ok_pattern -f $offsets.Count
            } else {
                $sync.M.m_dv_ok_rand -f $offsets.Count
            }
            WLog ($sync.M.m_dv_log -f $verifyResult)
        }

        $fs.Close(); $fs = $null
        $handle.Close(); $handle = $null

        # 6) Make the disk reusable again
        if ($online) { Set-Disk -Number $n -IsOffline $false -ErrorAction SilentlyContinue }
        Start-Sleep -Milliseconds 800
        if ($sync.Format) {
            $sync.Status = $sync.M.m_status_format
            WLog $sync.M.m_format_log
            try {
                $style = 'GPT'; $ds = 'NTFS'
                if ($sync.Bus -eq 'USB') { $style = 'MBR'; $ds = 'exFAT' }
                Assert-DiskProtection 'pre-format'
                Initialize-Disk -Number $n -PartitionStyle $style -ErrorAction Stop | Out-Null
                $partition = New-Partition -DiskNumber $n -UseMaximumSize -AssignDriveLetter -ErrorAction Stop
                Start-Sleep -Milliseconds 500
                # Volume label: derived from the disk make/model (exFAT <= 11, NTFS <= 32 chars)
                $label = ("$($sync.Model)".ToUpperInvariant() -replace '[^A-Z0-9]', '')
                $limit = if ($ds -eq 'NTFS') { 32 } else { 11 }
                if ($label.Length -gt $limit) { $label = $label.Substring(0, $limit) }
                if ([string]::IsNullOrWhiteSpace($label)) { $label = 'WIPED' }
                Format-Volume -DriveLetter $partition.DriveLetter -FileSystem $ds -NewFileSystemLabel $label -Confirm:$false -ErrorAction Stop | Out-Null
                WLog ($sync.M.m_disk_ready -f $partition.DriveLetter, $ds)
                if ($sync.Type -eq 'SSD') {
                    try {
                        $sync.Status = $sync.M.m_status_trim
                        WLog $sync.M.m_trim_start
                        Optimize-Volume -DriveLetter $partition.DriveLetter -ReTrim -ErrorAction Stop
                        $sync.TrimApplied = $true
                        WLog $sync.M.m_trim_ok
                    } catch {
                        WLog ($sync.M.m_trim_error -f $_.Exception.Message)
                    }
                }
            } catch {
                WLog ($sync.M.m_format_skipped -f $_.Exception.Message)
            }
        }
        elseif ($sync.Type -eq 'SSD') {
            WLog $sync.M.m_trim_none_partition
        }

        # 7) Destruction report (NIST 800-88 certificate format)
        $duration = (Get-Date) - $startTime
        $sync.DurationMin = [int]$duration.TotalMinutes
        $sync.DurationSec = [int]$duration.Seconds
        $sync.DvResult = $verifyResult
        if ($sync.Report) {
            $trimM = if ($sync.TrimApplied) { $sync.M.m_trim_applied } else { $sync.M.m_trim_notapplied }
            $report = $sync.M.r_template -f `
                (Get-Date -Format 'dd.MM.yyyy HH:mm:ss'), $env:COMPUTERNAME, $env:USERNAME, `
                $n, $sync.Model, $sync.Serial, [math]::Round($size/1GB,2), $size, $sync.Type, $sync.Bus, `
                $sync.CapabilitySummary, $sync.HealthSummary, $sync.MethodName, $passCount, `
                [math]::Round(($size * $passCount)/1GB,2), $verifyResult, $trimM, `
                [int]$duration.TotalMinutes, $duration.Seconds, $sync.RecommendationSummary
            $reportFolder = if ($sync.ReportFolder -and (Test-Path $sync.ReportFolder -PathType Container)) { $sync.ReportFolder } else { [Environment]::GetFolderPath('Desktop') }
            $reportPath = Join-Path $reportFolder ("DataDestructionReport_Disk{0}_{1}.txt" -f $n, (Get-Date -Format 'yyyyMMdd_HHmmss'))
            [System.IO.File]::WriteAllText($reportPath, $report)
            $sync.ReportPath = $reportPath
            WLog ($sync.M.m_report_saved -f $reportPath)
        }

        $sync.Status = $sync.M.m_status_done
        WLog $sync.M.m_op_ok
        $sync.Done = $true
    }
    catch {
        if ($fs) { try { $fs.Close() } catch { } }
        if ($handle) { try { $handle.Close() } catch { } }
        if ($online) { try { Set-Disk -Number $sync.DiskNo -IsOffline $false -ErrorAction SilentlyContinue } catch { } }
        if ("$_" -like '*__CANCEL__*') {
            $sync.Error = $sync.M.m_cancel
        } else {
            $sync.Error = ($sync.M.m_error -f $_.Exception.Message)
        }
        WLog $sync.Error
        $sync.Done = $true
    }
    finally {
        # Always release the cryptographic RNG and any open handles
        if ($null -ne $rng) { try { $rng.Dispose() } catch { } }
        if ($fs) { try { $fs.Dispose() } catch { } }
        if ($handle -and -not $handle.IsClosed) { try { $handle.Dispose() } catch { } }
    }
}

# ============================ EVENT HANDLERS =============================
$script:sync     = $null
$script:ps       = $null
$script:lastByte  = 0L
$script:lastTime = Get-Date

$timer = New-Object System.Windows.Threading.DispatcherTimer
$timer.Interval = [TimeSpan]::FromMilliseconds(300)
# ---- Event/queue state variables ----------------------------------------
$script:queue      = New-Object System.Collections.Generic.Queue[object]
$script:reportPaths = New-Object System.Collections.Generic.List[string]
$script:toEject = New-Object System.Collections.Generic.List[int]
$script:taskbarOn   = $true
$script:taskbarEject  = $true
$script:wipedCount = 0
$script:tempPoints = New-Object System.Collections.Generic.List[double]
$script:tempMax      = $null
$script:lastTempTime = (Get-Date).AddSeconds(-30)
$script:uiReady     = $false

# ---- Read-only physical disk opener (UI thread) ---------------------------
function Open-PhysicalDrive([int]$n) {
    if (-not ('GsLocal' -as [type])) {
        Add-Type -TypeDefinition @"
using System;
using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
public static class GsLocal {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern SafeFileHandle CreateFile(string lpFileName, uint dwDesiredAccess,
        uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition,
        uint dwFlagsAndAttributes, IntPtr hTemplateFile);
}
"@
    }
    $ACCESS_READ = [uint32]2147483648   # 0x80000000 = GENERIC_READ
    $handle = [GsLocal]::CreateFile("\\.\PHYSICALDRIVE$n", $ACCESS_READ, [uint32]3, [IntPtr]::Zero, [uint32]3, [uint32]0, [IntPtr]::Zero)
    if ($handle.IsInvalid) {
        throw ($script:Text.m_raw_error -f [Runtime.InteropServices.Marshal]::GetLastWin32Error())
    }
    # bufferSize=512: internal buffer fill cannot exceed the disk boundary (avoids false errors)
    return @{ H = $handle; FS = (New-Object System.IO.FileStream($handle, [System.IO.FileAccess]::Read, 512)) }
}

# ---- UI lock ----------------------------------------------------------
function Set-UiLock([bool]$lock) {
    $isOn = -not $lock
    $btnWipe.IsEnabled    = $isOn
    $btnRefresh.IsEnabled = $isOn
    $btnSpeed.IsEnabled    = $isOn
    $btnTrace.IsEnabled     = $isOn
    $btnSurface.IsEnabled  = $isOn
    $lstDisks.IsEnabled = $isOn
    $cmbMethod.IsEnabled = $isOn
    $cmbTheme.IsEnabled   = $isOn
    $btnCancel.IsEnabled  = $lock
}

# ---- Live temperature monitoring -------------------------------------------------
function Reset-Temperature {
    $script:tempPoints.Clear()
    $script:tempMax = $null
    $script:lastTempTime = (Get-Date).AddSeconds(-30)
    $txtTemp.Text = ''
    $plTemp.Points = New-Object System.Windows.Media.PointCollection
    $brdTemp.Visibility = 'Collapsed'
}

# ---- Taskbar progress state ------------------------------------------
function Set-TaskbarProgress([string]$status) {
    if (-not $tbItem) { return }
    try {
        $tbItem.ProgressState = $status        # None | Normal | Error | Paused | Indeterminate
        if ($status -eq 'None') { $tbItem.ProgressValue = 0 }
    } catch { }
}

function Sample-Temperature([int]$diskNo) {
    $now = Get-Date
    if (($now - $script:lastTempTime).TotalSeconds -lt 10) { return }
    $script:lastTempTime = $now
    $degrees = $null
    try {
        $rc = Get-PhysicalDisk -DeviceNumber $diskNo -ErrorAction Stop | Get-StorageReliabilityCounter -ErrorAction Stop
        if ($rc -and $null -ne $rc.Temperature -and $rc.Temperature -gt 0) { $degrees = [int]$rc.Temperature }
    } catch { }
    if ($null -eq $degrees) { return }

    $script:tempPoints.Add([double]$degrees)
    while ($script:tempPoints.Count -gt 60) { $script:tempPoints.RemoveAt(0) }
    if ($null -eq $script:tempMax -or $degrees -gt $script:tempMax) { $script:tempMax = $degrees }

    $txtTemp.Text = (T 'temp_fmt') -f $degrees, $script:tempMax

    $n = $script:tempPoints.Count
    if ($n -ge 2) {
        $min = ($script:tempPoints | Measure-Object -Minimum).Minimum
        $max = ($script:tempPoints | Measure-Object -Maximum).Maximum
        $range = [Math]::Max(1.0, $max - $min)
        $pc = New-Object System.Windows.Media.PointCollection
        for ($i = 0; $i -lt $n; $i++) {
            $x = if ($n -eq 1) { 0 } else { $i * 260.0 / ($n - 1) }
            $y = 28.0 - (($script:tempPoints[$i] - $min) / $range) * 24.0
            $pc.Add((New-Object System.Windows.Point($x, $y)))
        }
        $plTemp.Points = $pc
        $brdTemp.Visibility = 'Visible'
    }
}

# ---- PDF/HTML destruction certificate (with QR verification code) ------------------------
function Export-Certificate($s) {
    try {
        Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue
        if (-not $s.ReportPath -or -not (Test-Path $s.ReportPath)) { return }
        $content = Get-Content $s.ReportPath -Raw -Encoding UTF8
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $hashByte = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($content))
        $sha.Dispose()
        $hashHex = -join ($hashByte | ForEach-Object { $_.ToString('x2') })
        $code = $hashHex.Substring(0, 16).ToUpper()
        $showCode = ($code -replace '(.{4})(?!$)', '$1-')

        $date = Get-Date -Format 'dd.MM.yyyy HH:mm:ss'
        $durationStr = '{0}:{1:d2}' -f [int]$s.DurationMin, [int]$s.DurationSec

        # v2.1: The certificate is generated fully OFFLINE - the app makes no network
        # connection. Verification is done via the code + full SHA-256 digest.

        $tempRow = ''
        if ($null -ne $s.PeakTemp) {
            $tempRow = "<tr><td class='e'>$(T 'cert_field_temp')</td><td class='d'>$($s.PeakTemp) C</td></tr>"
        }

        $html = @"
<!DOCTYPE html><html><head><meta charset='utf-8'><style>
@page { size: A4; margin: 18mm; }
body { font-family: 'Segoe UI', Arial, sans-serif; color: #1b1d23; }
.frame { border: 3px double #2e3440; padding: 26px 30px; }
.inner { border: 1px solid #b8c0cc; padding: 24px 26px; }
h1 { text-align:center; font-size: 22px; letter-spacing:1px; margin:0 0 4px 0; color:#1f4e79; }
.sub { text-align:center; color:#5b6472; font-size:12px; margin-bottom:20px; }
table { width:100%; border-collapse:collapse; font-size:13px; }
td { padding:6px 8px; vertical-align:top; border-bottom:1px solid #e3e7ee; }
td.e { color:#5b6472; width:34%; }
td.d { color:#1b1d23; font-weight:600; }
.result { margin-top:16px; padding:10px 14px; background:#eaf4ea; border:1px solid #3e7a3e; color:#2f5e2f; font-weight:bold; text-align:center; border-radius:4px; }
.verifybox { margin-top:22px; display:flex; align-items:center; gap:18px; }
.verifybox .text { flex:1; }
.verifybox .title { color:#5b6472; font-size:11px; text-transform:uppercase; letter-spacing:1px; }
.verifybox .codebig { font-family:Consolas,monospace; font-size:20px; letter-spacing:2px; color:#1b1d23; }
.sha { font-family:Consolas,monospace; font-size:9px; color:#9aa5b1; margin-top:6px; word-break:break-all; }
.footer { margin-top:18px; text-align:center; color:#9aa5b1; font-size:10px; }
</style></head><body>
<div class='frame'><div class='inner'>
<h1>$(T 'cert_title')</h1>
<div class='sub'>$(T 'cert_sub')</div>
<table>
<tr><td class='e'>$(T 'cert_field_disk')</td><td class='d'>Disk $($s.DiskNo) &mdash; $([System.Web.HttpUtility]::HtmlEncode($s.Model))</td></tr>
<tr><td class='e'>$(T 'cert_field_serial')</td><td class='d'>$([System.Web.HttpUtility]::HtmlEncode($s.Serial))</td></tr>
<tr><td class='e'>$(T 'cert_field_capacity')</td><td class='d'>$([math]::Round($s.SizeBytes/1GB,2)) GB</td></tr>
<tr><td class='e'>$(T 'cert_field_method')</td><td class='d'>$([System.Web.HttpUtility]::HtmlEncode($s.MethodName))</td></tr>
<tr><td class='e'>$(T 'cert_field_pass')</td><td class='d'>$($s.Passes.Count)</td></tr>
<tr><td class='e'>$(T 'cert_field_dv')</td><td class='d'>$([System.Web.HttpUtility]::HtmlEncode([string]$s.DvResult))</td></tr>
<tr><td class='e'>$(T 'cert_field_duration')</td><td class='d'>$durationStr</td></tr>
<tr><td class='e'>$(T 'cert_field_health')</td><td class='d'>$([System.Web.HttpUtility]::HtmlEncode([string]$s.HealthSummary))</td></tr>
$tempRow
<tr><td class='e'>$(T 'cert_field_date')</td><td class='d'>$date</td></tr>
<tr><td class='e'>$(T 'cert_field_pc')</td><td class='d'>$env:COMPUTERNAME / $env:USERNAME</td></tr>
</table>
<div class='result'>$(T 'cert_field_result'): $(T 'cert_result')</div>
<div class='verifybox'>
  <div class='text'>
    <div class='title'>$(T 'cert_verification')</div>
    <div class='codebig'>$showCode</div>
    <div class='sha'>SHA-256: $hashHex</div>
  </div>
</div>
<div class='footer'>Strix Disk Cleaner v2.3 &bull; NIST SP 800-88 Rev.1</div>
</div></div>
</body></html>
"@
        $ts = Get-Date -Format 'yyyyMMdd_HHmmss'
        $htmlPath = Join-Path $env:TEMP ("SDC_Certificate_$ts.html")
        [System.IO.File]::WriteAllText($htmlPath, $html, [System.Text.Encoding]::UTF8)

        $desktop = if ($s.ReportFolder -and (Test-Path $s.ReportFolder -PathType Container)) { $s.ReportFolder } else { [Environment]::GetFolderPath('Desktop') }
        $pdfPath = Join-Path $desktop ("DataDestructionCertificate_Disk{0}_{1}.pdf" -f $s.DiskNo, $ts)

        $edges = @(
            (Join-Path ${env:ProgramFiles(x86)} 'Microsoft\Edge\Application\msedge.exe'),
            (Join-Path $env:ProgramFiles 'Microsoft\Edge\Application\msedge.exe')
        )
        $edge = $edges | Where-Object { Test-Path $_ } | Select-Object -First 1

        if ($edge) {
            $htmlUri = ([Uri]$htmlPath).AbsoluteUri
            $edgeArgs = @('--headless','--disable-gpu',"--print-to-pdf=`"$pdfPath`"","`"$htmlUri`"")
            $p = Start-Process -FilePath $edge -ArgumentList $edgeArgs -WindowStyle Hidden -PassThru
            if (-not $p.WaitForExit(30000)) { try { $p.Kill() } catch { } }
            if (Test-Path $pdfPath) {
                Add-LogEntry ((T 'pdf_ok_log') -f $pdfPath)
                $script:reportPaths.Add($pdfPath)
                try { Remove-Item $htmlPath -Force -ErrorAction SilentlyContinue } catch { }
                return
            }
        }
        # No Edge / no PDF produced -> drop the HTML certificate on the desktop
        $htmlTarget = Join-Path $desktop ("DataDestructionCertificate_Disk{0}_{1}.html" -f $s.DiskNo, $ts)
        Copy-Item $htmlPath $htmlTarget -Force
        Add-LogEntry ((T 'pdf_html_log') -f $htmlTarget)
        $script:reportPaths.Add($htmlTarget)
    } catch {
        Add-LogEntry ((T 'pdf_error_log') -f $_.Exception.Message)
    }
}

# ---- Start the worker inside a runspace -----------------------------------------
function Start-Worker($script) {
    $runspace = [runspacefactory]::CreateRunspace()
    $runspace.ApartmentState = 'MTA'
    $runspace.Open()
    $runspace.SessionStateProxy.SetVariable('sync', $script:sync)
    $script:ps = [powershell]::Create()
    $script:ps.Runspace = $runspace
    [void]$script:ps.AddScript($script.ToString()).AddArgument($script:sync)
    [void]$script:ps.BeginInvoke()
    $timer.Start()
}

# ---- Start wiping a single disk (called from the queue) --------------------------
function Start-Wipe($selection) {
    $blocked = Test-SafetyWall $selection.Number $selection.Serial
    if ($blocked) {
        Add-LogEntry ((T 'protect_block_log') -f $blocked)
        [System.Windows.MessageBox]::Show(
            ((T 'protect_block_msg') -f $blocked),
            (T 'protect_block_title'), 'OK', 'Stop') | Out-Null
        return $false
    }
    $method = Get-WipeMethod

    $y = Get-Capabilities $selection.Number $selection.Bus $selection.Type
    $detect = New-Recommendation $selection $y
    $health = Get-HealthSummary (Get-HealthInfo ([int]$selection.Number)) $selection.Type

    $script:sync = [hashtable]::Synchronized(@{
        DiskNo      = $selection.Number
        Model       = $selection.Model
        Serial        = $selection.Serial
        Type         = $selection.Type
        Bus    = $selection.Bus
        SizeBytes      = $selection.SizeBytes
        MethodName    = $method.Name
        Passes    = $method.Passes
        Verify     = [bool]$chkVerify.IsChecked
        Format = [bool]$chkFormat.IsChecked
        Report       = ([bool]$chkReport.IsChecked -or [bool]$chkPdf.IsChecked)
        ReportFolder = (Get-ReportFolder)
        CapabilitySummary = $detect.Summary
        RecommendationSummary   = $detect.Recommendation
        HealthSummary  = $(if ($health) { $health } else { 'Not queried' })
        TrimApplied = $false
        ProtectedNumbers = @($script:protection.Numbers.Keys | ForEach-Object { [int]$_ })
        ProtectedSerials    = @($script:protection.Serials)
        ExpectedSerial     = "$($selection.Serial)".Trim()
        SystemDrive     = $env:SystemDrive
        TotalBytes  = [long]$selection.SizeBytes * $method.Passes.Count
        DoneBytes   = 0L
        BaseBytes   = 0L
        Status       = 'Starting...'
        Pass       = ''
        Record       = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
        Cancel       = $false
        Done       = $false
        Error        = $null
        ReportPath    = $null
        Mod         = 'wipe'
        M           = $script:Text
        DurationMin      = 0
        DurationSec      = 0
        DvResult     = ''
        PeakTemp      = $null
    })

    Set-UiLock $true
    Reset-Temperature
    $txtStatus.Foreground = $script:Theme.WARNFG
    $prgProgress.Value = 0
    $script:lastByte = 0L; $script:lastTime = Get-Date
    Add-LogEntry ((T 'wipe_started_log') -f $selection.Number, $method.Name)
    Start-Worker $workerScript
    return $true
}

# ---- Advance to the next disk in the queue ------------------------------------------
function Step-Queue {
    while ($script:queue.Count -gt 0) {
        $next = $script:queue.Dequeue()
        Add-LogEntry ((T 'queue_next_log') -f $next.Number)
        if (Start-Wipe $next) { return $true }
    }
    return $false
}

# ---- Data-trace scan worker script (entropy sampling, read-only) --------
$traceScript = {
    param($sync)
    $fs = $null; $handle = $null
    try {
        if (-not ('GsLocal' -as [type])) {
            Add-Type -TypeDefinition @"
using System;
using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
public static class GsLocal {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern SafeFileHandle CreateFile(string lpFileName, uint dwDesiredAccess,
        uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition,
        uint dwFlagsAndAttributes, IntPtr hTemplateFile);
}
"@
        }
        $n = [int]$sync.DiskNo
        $ACCESS_READ = [uint32]2147483648
        $handle = [GsLocal]::CreateFile("\\.\PHYSICALDRIVE$n", $ACCESS_READ, [uint32]3, [IntPtr]::Zero, [uint32]3, [uint32]0, [IntPtr]::Zero)
        if ($handle.IsInvalid) { throw ($sync.M.m_raw_error -f [Runtime.InteropServices.Marshal]::GetLastWin32Error()) }
        $fs = New-Object System.IO.FileStream($handle, [System.IO.FileAccess]::Read, 512)

        $sync.Status = $sync.M.trace_status
        $total = [long]$sync.SizeBytes
        $total = $total - ($total % 512)
        $blockSize = 4096
        $buf = New-Object byte[] $blockSize

        $offsets = New-Object System.Collections.Generic.List[long]
        $offsets.Add(0L)
        $lastOffset = [long][Math]::Floor(($total - $blockSize) / [double]$blockSize) * $blockSize
        if ($lastOffset -gt 0) { $offsets.Add($lastOffset) }
        $rng = New-Object System.Random
        $maxVal = [long][Math]::Max(1, [long]($total / $blockSize) - 1)
        for ($i = 0; $i -lt 256; $i++) {
            $offsets.Add(([long]($rng.NextDouble() * $maxVal)) * $blockSize)
        }
        $sync.TotalBytes = [long]$offsets.Count * $blockSize

        $zero = 0; $ff = 0; $data = 0; $entTotal = 0.0; $num = 0
        for ($i = 0; $i -lt $offsets.Count; $i++) {
            if ($sync.Cancel) { throw '__CANCEL__' }
            try {
                $fs.Position = $offsets[$i]
                $readBytes = $fs.Read($buf, 0, $blockSize)
                if ($readBytes -gt 0) {
                    $result = [GsAnalyze]::Inspect($buf, $readBytes)
                    switch ([int]$result[0]) {
                        0 { $zero++ }
                        1 { $ff++ }
                        2 { $data++ }
                    }
                    $entTotal += $result[1]
                    $num++
                }
            } catch { }
            $sync.DoneBytes = [long]($i + 1) * $blockSize
        }
        $sync.TraceZero = $zero
        $sync.TraceFF    = $ff
        $sync.TraceData  = $data
        $sync.TraceCount   = $num
        if ($num -gt 0) { $sync.TraceEntropy = $entTotal / $num } else { $sync.TraceEntropy = 0.0 }
    } catch {
        if ("$($_.Exception.Message)" -eq '__CANCEL__') { $sync.Error = $sync.M.m_cancel_read }
        else { $sync.Error = ($sync.M.m_error -f $_.Exception.Message) }
    } finally {
        if ($fs) { try { $fs.Dispose() } catch { } }
        if ($handle -and -not $handle.IsClosed) { try { $handle.Dispose() } catch { } }
        $sync.Done = $true
    }
}

# ---- Surface test worker script (read-only) ---------------------------------
$surfaceScript = {
    param($sync)
    function WLog([string]$m) { [void]$sync.Record.Add(('[{0}] {1}' -f (Get-Date -Format 'HH:mm:ss'), $m)) }
    $fs = $null; $handle = $null
    try {
        if (-not ('GsLocal' -as [type])) {
            Add-Type -TypeDefinition @"
using System;
using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
public static class GsLocal {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern SafeFileHandle CreateFile(string lpFileName, uint dwDesiredAccess,
        uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition,
        uint dwFlagsAndAttributes, IntPtr hTemplateFile);
}
"@
        }
        $n = [int]$sync.DiskNo
        $ACCESS_READ = [uint32]2147483648
        $handle = [GsLocal]::CreateFile("\\.\PHYSICALDRIVE$n", $ACCESS_READ, [uint32]3, [IntPtr]::Zero, [uint32]3, [uint32]0, [IntPtr]::Zero)
        if ($handle.IsInvalid) { throw ($sync.M.m_raw_error -f [Runtime.InteropServices.Marshal]::GetLastWin32Error()) }
        # bufferSize=512: each read is direct; internal buffer fill cannot run
        # past the disk end and produce a false read error on a healthy disk
        $fs = New-Object System.IO.FileStream($handle, [System.IO.FileAccess]::Read, 512)

        $sync.Status = $sync.M.m_y_status
        $total = [long]$sync.TotalBytes
        $total = $total - ($total % 512)   # raw access: sector-aligned end
        $part  = 4MB
        $buf    = New-Object byte[] $part
        $subSize = 64KB
        $pos = 0L
        while ($pos -lt $total) {
            if ($sync.Cancel) { throw '__CANCEL__' }
            $read = [int][Math]::Min([long]$part, $total - $pos)
            $succeeded = $true
            try {
                $fs.Position = $pos
                [void]$fs.Read($buf, 0, $read)
            } catch { $succeeded = $false }

            if (-not $succeeded) {
                # Split the block into 64 KB sub-blocks to narrow the bad region
                # (seeks on the same stream and retries the read; a read error
                #  does not corrupt the FileStream, so the next position is reachable)
                $subBuf = New-Object byte[] $subSize
                $subNum = 0
                $subCount = [int][Math]::Ceiling($read / [double]$subSize)
                for ($j = 0; $j -lt $subCount; $j++) {
                    if ($sync.Cancel) { throw '__CANCEL__' }
                    $subPos = $pos + ([long]$j * $subSize)
                    $subRead = [int][Math]::Min([long]$subSize, $total - $subPos)
                    if ($subRead -le 0) { break }
                    try {
                        $fs.Position = $subPos
                        [void]$fs.Read($subBuf, 0, $subRead)
                    } catch {
                        $subNum++
                        $sync.BadCount = [int]$sync.BadCount + 1
                        if ($sync.BadOffsets.Count -lt 50) { [void]$sync.BadOffsets.Add($subPos) }
                    }
                }
                if ($subNum -gt 0) { WLog ($sync.M.m_y_error -f $pos, $subNum) }
            }

            $pos += $read
            $sync.DoneBytes = $pos
        }

        if ([int]$sync.BadCount -eq 0) { WLog $sync.M.m_y_ok }
        else { WLog ($sync.M.m_y_done -f [int]$sync.BadCount) }
    } catch {
        if ("$($_.Exception.Message)" -eq '__CANCEL__') { $sync.Error = $sync.M.m_cancel_read }
        else { $sync.Error = ($sync.M.m_error -f $_.Exception.Message) }
    } finally {
        if ($fs) { try { $fs.Dispose() } catch { } }
        if ($handle -and -not $handle.IsClosed) { try { $handle.Dispose() } catch { } }
        $sync.Done = $true
    }
}

# ============================ TIMER ===================================
$timer.Add_Tick({
    $s = $script:sync
    if ($null -eq $s) { return }

    while ($s.Record.Count -gt 0) {
        $txtLog.AppendText("$($s.Record[0])" + [Environment]::NewLine)
        $s.Record.RemoveAt(0)
        $txtLog.ScrollToEnd()
    }

    $txtStatus.Text = "$($s.Status)"
    $txtPass.Text = "$($s.Pass)"

    $total = [double]$s.TotalBytes
    $doneBytes  = [double]$s.DoneBytes
    if ($total -gt 0) {
        $percent = [Math]::Min(100, $doneBytes / $total * 100)
        $prgProgress.Value = $percent
        $txtPercent.Text = ('%{0:N1}  ({1} / {2})' -f $percent, (Format-Size ([long]$doneBytes)), (Format-Size ([long]$total)))
        # Taskbar progress (unless the user disabled it)
        if ($script:taskbarOn -and $tbItem) {
            try {
                if ($tbItem.ProgressState -ne 'Normal') { $tbItem.ProgressState = 'Normal' }
                $tbItem.ProgressValue = [Math]::Min(1.0, $doneBytes / $total)
            } catch { }
        }

        $now = Get-Date
        $elapsed = ($now - $script:lastTime).TotalSeconds
        if ($elapsed -ge 1.0) {
            $speed = ($doneBytes - $script:lastByte) / $elapsed
            $script:lastByte = $doneBytes; $script:lastTime = $now
            if ($speed -gt 0) {
                $txtSpeed.Text = ((T 't_speed') -f (Format-Size ([long]$speed)))
                $remainSec = ($total - $doneBytes) / $speed
                $txtRemain.Text = ((T 't_remaining') -f ('{0:hh\:mm\:ss}' -f [TimeSpan]::FromSeconds($remainSec)))
            }
        }
    }

    # Live temperature during wiping
    if ($s.Mod -eq 'wipe' -and -not $s.Done) { Sample-Temperature ([int]$s.DiskNo) }

    if ($s.Done) {
        $timer.Stop()

        if ($s.Error) {
            Set-UiLock $false
            Set-TaskbarProgress 'Error'
            $txtStatus.Text = "$($s.Error)"
            $txtStatus.Foreground = 'IndianRed'
            Show-Notification $false
            if ($script:queue.Count -gt 0) { $script:queue.Clear(); Add-LogEntry (T 'queue_cancel_log') }
            [System.Windows.MessageBox]::Show($s.Error, 'Strix Disk Cleaner', 'OK', 'Warning') | Out-Null
            Set-TaskbarProgress 'None'
            if ($script:ps) { $script:ps.Dispose(); $script:ps = $null }
            $script:sync = $null
            Reset-Temperature
            Update-DiskList
            return
        }

        if ($s.Mod -eq 'surface') {
            Set-UiLock $false
            $txtStatus.Foreground = $script:Theme.OK
            $bad = [int]$s.BadCount
            Show-Notification ($bad -eq 0)
            if ($bad -eq 0) {
                [System.Windows.MessageBox]::Show((T 'surface_ok_msg'), (T 'surface_title'), 'OK', 'Information') | Out-Null
            } else {
                $first = ($s.BadOffsets | Select-Object -First 10 | ForEach-Object { '{0:N0}' -f $_ }) -join "`n"
                [System.Windows.MessageBox]::Show(((T 'surface_bad_msg') -f $bad, $first), (T 'surface_title'), 'OK', 'Warning') | Out-Null
            }
            if ($script:ps) { $script:ps.Dispose(); $script:ps = $null }
            $script:sync = $null
            $txtStatus.Text = (T 'status_ready')
            return
        }

        if ($s.Mod -eq 'trace') {
            Set-UiLock $false
            $prgProgress.Value = 100
            $txtStatus.Foreground = $script:Theme.OK
            $num = [int]$s.TraceCount
            $dataPct = if ($num -gt 0) { [math]::Round([int]$s.TraceData * 100.0 / $num, 1) } else { 0 }
            $summary = (T 'trace_summary') -f $num, [int]$s.TraceData, $dataPct, [int]$s.TraceZero, [int]$s.TraceFF, [double]$s.TraceEntropy
            # Smart interpretation: 1-2 filled blocks + ~zero entropy = partition structures only (clean)
            $interpretation = if ([int]$s.TraceData -eq 0) {
                         (T 'trace_note_empty')
                     } elseif ([int]$s.TraceData -le 2 -and [double]$s.TraceEntropy -lt 1.0) {
                         (T 'trace_note_clean')
                     } elseif ([double]$s.TraceEntropy -ge 7.3) {
                         (T 'trace_note_encrypted')
                     } else {
                         (T 'trace_note_present')
                     }
            Add-LogEntry $summary
            Add-LogEntry $interpretation
            Show-Notification $true
            [System.Windows.MessageBox]::Show("$summary`n`n$interpretation", (T 'trace_title'), 'OK', 'Information') | Out-Null
            if ($script:ps) { $script:ps.Dispose(); $script:ps = $null }
            $script:sync = $null
            $txtStatus.Text = (T 'status_ready')
            return
        }

        # --- Wipe finished successfully ---
        $prgProgress.Value = 100
        $txtStatus.Foreground = $script:Theme.OK

        if ($null -ne $script:tempMax) {
            $s.PeakTemp = $script:tempMax
            Add-LogEntry ((T 'temp_report') -f $script:tempMax)
        }

        if ($s.ReportPath) {
            if ([bool]$chkPdf.IsChecked) { Export-Certificate $s }
            if ([bool]$chkReport.IsChecked) {
                $script:reportPaths.Add($s.ReportPath)
            } else {
                # Only PDF was requested; remove the intermediate .txt report
                try { Remove-Item $s.ReportPath -Force -ErrorAction SilentlyContinue } catch { }
            }
        }
        $script:wipedCount++

        if ($script:ps) { $script:ps.Dispose(); $script:ps = $null }
        $script:sync = $null
        Reset-Temperature

        if ($script:queue.Count -gt 0) {
            if (Step-Queue) { return }
        }

        Set-UiLock $false
        Set-TaskbarProgress 'None'
        Show-Notification $true
        # Safely eject USB disks when done (if the user asked for it)
        if ($script:taskbarEject -and $script:toEject.Count -gt 0) {
            foreach ($cd in $script:toEject) { Eject-Disk ([int]$cd) }
        }
        $script:toEject.Clear()
        $message = (T 'done_msg') -f $script:wipedCount
        if ($script:reportPaths.Count -gt 0) {
            $message += (T 'report_msg') + "`n" + (($script:reportPaths | ForEach-Object { Split-Path $_ -Leaf }) -join "`n")
        }
        [System.Windows.MessageBox]::Show($message, (T 'success_title'), 'OK', 'Information') | Out-Null
        $script:wipedCount = 0
        $script:reportPaths.Clear()
        Update-DiskList
    }
})

# ============================ EVENT HANDLERS =============================
$lstDisks.Add_SelectionChanged({
  try {
    $selection = $lstDisks.SelectedItem
    if ($null -eq $selection) {
        $pnlSsdWarn.Visibility = 'Collapsed'; $script:lastDetect = $null; $script:lastHealth = $null
        $script:lastHidden = $null; return
    }
    $y = Get-Capabilities $selection.Number $selection.Bus $selection.Type
    $script:lastDetect = New-Recommendation $selection $y
    $script:lastHealth = Get-HealthSummary (Get-HealthInfo ([int]$selection.Number)) $selection.Type

    # Hidden-area (HPA/DCO) detection
    $script:lastHidden = Get-HiddenArea ([int]$selection.Number) $selection.Bus
    $hiddenText = ''
    if ($script:lastHidden.Present) {
        $hiddenText = "`n`n[!] " + ((T 'hpa_present') -f (Format-Size $script:lastHidden.HiddenBytes), `
                       ($script:lastHidden.NativeSector - $script:lastHidden.UserSector))
    } elseif ($script:lastHidden.Queryable) {
        $hiddenText = "`n`n" + (T 'hpa_none')
    } else {
        $hiddenText = "`n`n" + (T 'hpa_query_none')
    }

    # Content preview (read-only)
    $preview = Get-PreviewText ([int]$selection.Number)

    $txtSsdWarn.Text = $script:lastDetect.Panel + $hiddenText + `
        "`n`n" + (T 'preview_title_panel') + "`n" + $preview + `
        "`n`n" + (T 'health_panel') + "`n  - " + ($script:lastHealth -replace ' \| ', "`n  - ")
    $btnUefi.Visibility = if ($selection.Type -eq 'SSD') { 'Visible' } else { 'Collapsed' }
    $pnlSsdWarn.Visibility = 'Visible'
  } catch {
    # A panel display error does NOT crash the app; it is logged for diagnostics.
    try {
        $log = Join-Path $env:TEMP 'StrixDiskCleaner_error.log'
        $t = "[{0}] SelectionChanged error`r`n{1}`r`nStack:`r`n{2}" -f (Get-Date), ($_ | Out-String), "$($_.ScriptStackTrace)"
        [System.IO.File]::WriteAllText($log, $t)
    } catch { }
    try { Add-LogEntry ("Panel display error: {0}" -f $_.Exception.Message) } catch { }
    $pnlSsdWarn.Visibility = 'Collapsed'
  }
})

$btnUefi.Add_Click({
    $answer = [System.Windows.MessageBox]::Show((T 'uefi_question'), (T 'uefi_title'), 'YesNo', 'Question')
    if ($answer -eq 'Yes') {
        Start-Process shutdown.exe -ArgumentList '/r','/fw','/t','5' -WindowStyle Hidden
    }
})

# ---- SMART raw attribute table -------------------------------------------
$btnSmart.Add_Click({
    $selection = $lstDisks.SelectedItem
    if ($null -eq $selection) {
        [System.Windows.MessageBox]::Show((T 'first_disk_select'), 'Strix Disk Cleaner', 'OK', 'Information') | Out-Null
        return
    }
    $n = [int]$selection.Number
    $rows = New-Object System.Collections.Generic.List[object]
    try {
        $dd = Get-CimInstance Win32_DiskDrive -Filter "Index=$n" -ErrorAction Stop
        $pnp = "$($dd.PNPDeviceID)".Trim()
        $smart = Get-CimInstance -Namespace root\wmi -Class MSStorageDriver_ATAPISmartData -ErrorAction Stop |
                 Where-Object { "$($_.InstanceName)" -like ($pnp + '*') } | Select-Object -First 1
        if ($smart -and $smart.VendorSpecific) {
            $vs = [byte[]]$smart.VendorSpecific
            # VendorSpecific: after a 2-byte header, 30 x 12-byte attribute records
            for ($o = 2; $o + 11 -lt $vs.Length; $o += 12) {
                $id = $vs[$o]
                if ($id -eq 0) { continue }
                $value = $vs[$o+3]
                $worst = $vs[$o+4]
                $raw = [long]0
                for ($b = 0; $b -lt 6; $b++) { $raw = $raw -bor ([long]$vs[$o+5+$b] -shl (8 * $b)) }
                $attrName = switch ($id) {
                    1   {'Read Error Rate'}       5   {'Reallocated Sectors'}
                    9   {'Power-On Hours'}        10  {'Spin Retry Count'}
                    12  {'Power Cycle Count'}     187 {'Reported Uncorrectable'}
                    188 {'Command Timeout'}       190 {'Airflow Temperature'}
                    194 {'Temperature'}           196 {'Reallocation Events'}
                    197 {'Current Pending Sectors'} 198 {'Offline Uncorrectable'}
                    199 {'UDMA CRC Error Count'}  231 {'SSD Life Left'}
                    241 {'Total LBAs Written'}    242 {'Total LBAs Read'}
                    default {"Attribute $id"}
                }
                # Status evaluation for critical attributes
                $status = T 'smart_ok'
                if (($id -in 5,197,198,187) -and $raw -gt 0) { $status = T 'smart_check' }
                $rows.Add([pscustomobject]@{
                    Id=$id; Name=$attrName; Value=$value; Worst=$worst; Raw=$raw; Status=$status
                })
            }
        }
    } catch { }

    if ($rows.Count -eq 0) {
        [System.Windows.MessageBox]::Show((T 'smart_none'), ((T 'smart_title') -f $n), 'OK', 'Information') | Out-Null
        return
    }

    $smartXaml = Expand-Xaml @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="SMART" Width="640" Height="520" WindowStartupLocation="CenterOwner" Background="%BG%">
  <Grid Margin="14">
    <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
    <TextBlock Name="smTitle" Grid.Row="0" FontSize="15" FontWeight="Bold" Foreground="%ACCENT%" Margin="0,0,0,8"/>
    <ListView Name="smList" Grid.Row="1" Background="%PANEL%" Foreground="%FG%" BorderBrush="%BORDER%" FontSize="12">
      <ListView.View>
        <GridView>
          <GridViewColumn Header="{T:smart_col_id}" Width="45" DisplayMemberBinding="{Binding Id}"/>
          <GridViewColumn Header="{T:smart_col_name}" Width="220" DisplayMemberBinding="{Binding Name}"/>
          <GridViewColumn Header="{T:smart_col_value}" Width="60" DisplayMemberBinding="{Binding Value}"/>
          <GridViewColumn Header="{T:smart_col_worst}" Width="60" DisplayMemberBinding="{Binding Worst}"/>
          <GridViewColumn Header="{T:smart_col_raw}" Width="130" DisplayMemberBinding="{Binding Raw}"/>
          <GridViewColumn Header="{T:smart_col_status}" Width="70" DisplayMemberBinding="{Binding Status}"/>
        </GridView>
      </ListView.View>
    </ListView>
    <Button Name="smClose" Grid.Row="2" Content="OK" HorizontalAlignment="Right" Margin="0,10,0,0" Padding="24,6"/>
  </Grid>
</Window>
'@
    $smRead = New-Object System.Xml.XmlNodeReader $smartXaml
    $smWindow = [Windows.Markup.XamlReader]::Load($smRead)
    if ($script:AppIcon) { try { $smWindow.Icon = $script:AppIcon } catch { } }
    $smWindow.Owner = $window
    $smWindow.FindName('smTitle').Text = ((T 'smart_title') -f $n) + "  -  $($selection.Model)"
    $smWindow.FindName('smList').ItemsSource = $rows
    $smWindow.FindName('smClose').Add_Click({ $smWindow.Close() })
    [void]$smWindow.ShowDialog()
})

# ---- Choose report folder ------------------------------------------------------
$btnReportFolder.Add_Click({
    Add-Type -AssemblyName System.Windows.Forms
    $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
    $dlg.Description = (T 'report_folder_title')
    $current = Get-ReportFolder
    try { $dlg.SelectedPath = $current } catch { }
    if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $script:Settings.ReportFolder = $dlg.SelectedPath
        $txtReportFolder.Text = $dlg.SelectedPath
        Save-Settings
    }
})

$btnRefresh.Add_Click({ Update-DiskList })

$btnCancel.Add_Click({
    if ($script:sync) {
        $question = if ($script:sync.Mod -eq 'surface' -or $script:sync.Mod -eq 'trace') { (T 'cancel_question_read') } else { (T 'cancel_question') }
        $answer = [System.Windows.MessageBox]::Show($question, (T 'cancel_title'), 'YesNo', 'Warning')
        if ($answer -eq 'Yes') { $script:sync.Cancel = $true }
    }
})

# ---- Speed test: read (always safe) + write (file-based / consented raw) --
$btnSpeed.Add_Click({
    $selection = $lstDisks.SelectedItem
    if ($null -eq $selection) {
        [System.Windows.MessageBox]::Show((T 'first_disk_select'), 'Strix Disk Cleaner', 'OK', 'Information') | Out-Null
        return
    }
    $n = [int]$selection.Number
    Set-UiLock $true; $btnCancel.IsEnabled = $false
    Add-LogEntry ((T 'speed_started_log') -f $n, $selection.Model)
    $hnd = $null; $fs = $null          # read (raw, read-only)
    $ws = $null; $tmp = $null          # write (temp file)
    $handleW = $null; $fsw = $null        # write (raw, consented)
    try {
        $part = 4MB
        $total = [long]$selection.SizeBytes

        # ---------- 1) READ: sequential ----------
        $drive = Open-PhysicalDrive $n
        $hnd = $drive.H; $fs = $drive.FS
        $buf = New-Object byte[] $part
        $limit = [long][Math]::Min($total, 512MB)
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $readBytes = 0L
        while ($readBytes -lt $limit -and $sw.Elapsed.TotalSeconds -lt 3.0) {
            $read = [int][Math]::Min([long]$part, $limit - $readBytes)
            [void]$fs.Read($buf, 0, $read)
            $readBytes += $read
            $txtStatus.Text = ((T 'speed_phase1') -f (Format-Size $readBytes))
            $window.Dispatcher.Invoke([action]{}, [System.Windows.Threading.DispatcherPriority]::Background)
        }
        $sw.Stop()
        $seqRead = if ($sw.Elapsed.TotalSeconds -gt 0) { $readBytes / $sw.Elapsed.TotalSeconds } else { 0 }

        # ---------- 2) READ: random 4K ----------
        $txtStatus.Text = (T 'speed_phase2')
        $window.Dispatcher.Invoke([action]{}, [System.Windows.Threading.DispatcherPriority]::Background)
        $buf4 = New-Object byte[] 4096
        $rnd = New-Object System.Random
        $maxBlock = [long][Math]::Max(1, [long]($total / 4096) - 1)
        $sw2 = [System.Diagnostics.Stopwatch]::StartNew()
        $readIops = 0
        while ($sw2.Elapsed.TotalSeconds -lt 2.0) {
            $fs.Position = ([long]($rnd.NextDouble() * $maxBlock)) * 4096
            [void]$fs.Read($buf4, 0, 4096)
            $readIops++
        }
        $sw2.Stop()
        $readIopsSec = if ($sw2.Elapsed.TotalSeconds -gt 0) { $readIops / $sw2.Elapsed.TotalSeconds } else { 0 }
        $readLatency = if ($readIopsSec -gt 0) { 1000.0 / $readIopsSec } else { 0 }
        $fs.Dispose(); $fs = $null
        if ($hnd -and -not $hnd.IsClosed) { $hnd.Dispose() }; $hnd = $null

        $readSummary = (T 'speed_read_summary') -f (Format-Size ([long]$seqRead)), $readIopsSec, $readLatency
        $writeSummary = $null

        # ---------- 3) Pick a WRITE target: is there a volume with enough free space? ----------
        $letter = $null
        try {
            foreach ($p in @(Get-Partition -DiskNumber $n -ErrorAction SilentlyContinue |
                             Where-Object { $_.DriveLetter })) {
                try {
                    $vol = Get-Volume -DriveLetter $p.DriveLetter -ErrorAction Stop
                    if ([long]$vol.SizeRemaining -ge 320MB) { $letter = "$($p.DriveLetter)"; break }
                } catch { }
            }
        } catch { }

        # Random test data (zeros can be misleading on SSD controllers)
        $rgen = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $writeBuf = New-Object byte[] $part
        $rgen.GetBytes($writeBuf)
        $write4 = New-Object byte[] 4096
        $rgen.GetBytes($write4)
        $rgen.Dispose()

        if ($letter) {
            # --- 3a) HARMLESS: write to a temp file on the volume with WriteThrough ---
            Add-LogEntry ((T 'speed_write_file_log') -f $letter)
            $tmp = "${letter}:\sdc_speedtest.tmp"
            $ws = New-Object System.IO.FileStream($tmp,
                    [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write,
                    [System.IO.FileShare]::None, $part, [System.IO.FileOptions]::WriteThrough)
            $yLimit = 256MB
            $sw3 = [System.Diagnostics.Stopwatch]::StartNew()
            $writtenBytes = 0L
            while ($writtenBytes -lt $yLimit -and $sw3.Elapsed.TotalSeconds -lt 3.0) {
                $bu = [int][Math]::Min([long]$part, $yLimit - $writtenBytes)
                $ws.Write($writeBuf, 0, $bu)
                $writtenBytes += $bu
                $txtStatus.Text = ((T 'speed_phase3') -f (Format-Size $writtenBytes))
                $window.Dispatcher.Invoke([action]{}, [System.Windows.Threading.DispatcherPriority]::Background)
            }
            $ws.Flush($true)
            $sw3.Stop()
            $seqWrite = if ($sw3.Elapsed.TotalSeconds -gt 0) { $writtenBytes / $sw3.Elapsed.TotalSeconds } else { 0 }
            $fileSize = $ws.Length
            $ws.Dispose(); $ws = $null

            # random 4K write (within the same file)
            $txtStatus.Text = (T 'speed_phase4')
            $window.Dispatcher.Invoke([action]{}, [System.Windows.Threading.DispatcherPriority]::Background)
            $ws = New-Object System.IO.FileStream($tmp,
                    [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write,
                    [System.IO.FileShare]::None, 4096, [System.IO.FileOptions]::WriteThrough)
            $maxByte = [long][Math]::Max(1, [long]($fileSize / 4096) - 1)
            $sw4 = [System.Diagnostics.Stopwatch]::StartNew()
            $writeIops = 0
            while ($sw4.Elapsed.TotalSeconds -lt 1.5) {
                $ws.Position = ([long]($rnd.NextDouble() * $maxByte)) * 4096
                $ws.Write($write4, 0, 4096)
                $writeIops++
            }
            $sw4.Stop()
            $ws.Dispose(); $ws = $null
            Remove-Item $tmp -Force -ErrorAction SilentlyContinue; $tmp = $null
            $writeIopsSec = if ($sw4.Elapsed.TotalSeconds -gt 0) { $writeIops / $sw4.Elapsed.TotalSeconds } else { 0 }
            $writeLatency = if ($writeIopsSec -gt 0) { 1000.0 / $writeIopsSec } else { 0 }
            $writeSummary = (T 'speed_write_summary') -f (Format-Size ([long]$seqWrite)), $writeIopsSec, $writeLatency
        }
        else {
            # --- 3b) RAW mode: only with EXPLICIT CONSENT, writes over the first 256 MB ---
            $answer = [System.Windows.MessageBox]::Show(
                ((T 'speed_write_raw_question') -f (Format-Size (256MB))),
                (T 'speed_title'), 'YesNo', 'Warning')
            if ($answer -eq 'Yes') {
                $blocked = Test-SafetyWall $n $selection.Serial
                if ($blocked) {
                    Add-LogEntry ((T 'protect_block_log') -f $blocked)
                    [System.Windows.MessageBox]::Show(((T 'protect_block_msg') -f $blocked),
                        (T 'protect_block_title'), 'OK', 'Stop') | Out-Null
                } else {
                    $ACCESS_RW = [uint32]3221225472   # GENERIC_READ|GENERIC_WRITE
                    $handleW = [GsLocal]::CreateFile("\\.\PHYSICALDRIVE$n", $ACCESS_RW, [uint32]3, [IntPtr]::Zero, [uint32]3, [uint32]0, [IntPtr]::Zero)
                    if ($handleW.IsInvalid) { throw ($script:Text.m_raw_error -f [Runtime.InteropServices.Marshal]::GetLastWin32Error()) }
                    $fsw = New-Object System.IO.FileStream($handleW, [System.IO.FileAccess]::Write)
                    $yLimit = [long][Math]::Min($total, 256MB)
                    $sw3 = [System.Diagnostics.Stopwatch]::StartNew()
                    $writtenBytes = 0L
                    while ($writtenBytes -lt $yLimit -and $sw3.Elapsed.TotalSeconds -lt 3.0) {
                        $bu = [int][Math]::Min([long]$part, $yLimit - $writtenBytes)
                        $fsw.Write($writeBuf, 0, $bu)
                        $writtenBytes += $bu
                        $txtStatus.Text = ((T 'speed_phase3') -f (Format-Size $writtenBytes))
                        $window.Dispatcher.Invoke([action]{}, [System.Windows.Threading.DispatcherPriority]::Background)
                    }
                    $fsw.Flush($true)   # cache-flushing write: keep the measurement consistent with the other phases
                    $sw3.Stop()
                    $fsw.Dispose(); $fsw = $null
                    if ($handleW -and -not $handleW.IsClosed) { $handleW.Dispose() }; $handleW = $null
                    $seqWrite = if ($sw3.Elapsed.TotalSeconds -gt 0) { $writtenBytes / $sw3.Elapsed.TotalSeconds } else { 0 }
                    $writeSummary = (T 'speed_write_raw_summary') -f (Format-Size ([long]$seqWrite))
                }
            } else {
                Add-LogEntry (T 'speed_write_none')
            }
        }

        # ---------- 4) Summary ----------
        $parts = New-Object System.Collections.Generic.List[string]
        $parts.Add($readSummary)
        if ($writeSummary) { $parts.Add($writeSummary) }
        Add-LogEntry ((T 'speed_done_log') -f ($parts -join '  ||  '))
        Add-LogEntry (T 'speed_note')
        $txtStatus.Text = (T 'speed_status')
        [System.Windows.MessageBox]::Show(
            ((T 'speed_msg') -f $n, $selection.Model, ($parts -join "`n")),
            (T 'speed_title'), 'OK', 'Information') | Out-Null
    } catch {
        Add-LogEntry ((T 'speed_error_log') -f $_.Exception.Message)
        $txtStatus.Text = ((T 'speed_error_log') -f $_.Exception.Message)
    } finally {
        if ($fs)  { try { $fs.Dispose()  } catch { } }
        if ($hnd  -and -not $hnd.IsClosed)  { try { $hnd.Dispose()  } catch { } }
        if ($ws)  { try { $ws.Dispose()  } catch { } }
        if ($fsw) { try { $fsw.Dispose() } catch { } }
        if ($handleW -and -not $handleW.IsClosed) { try { $handleW.Dispose() } catch { } }
        if ($tmp -and (Test-Path $tmp)) { try { Remove-Item $tmp -Force } catch { } }
        Set-UiLock $false
    }
})

# ---- Data-trace scan (entropy sampling, read-only, runspace) ----------
$btnTrace.Add_Click({
    $selection = $lstDisks.SelectedItem
    if ($null -eq $selection) {
        [System.Windows.MessageBox]::Show((T 'first_disk_select'), 'Strix Disk Cleaner', 'OK', 'Information') | Out-Null
        return
    }
    $script:sync = [hashtable]::Synchronized(@{
        DiskNo      = $selection.Number
        Model       = $selection.Model
        SizeBytes      = $selection.SizeBytes
        TotalBytes  = [long](258L * 4096)
        DoneBytes   = 0L
        Status       = (T 'trace_status')
        Pass       = ''
        Record       = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
        Cancel       = $false
        Done       = $false
        Error        = $null
        Mod         = 'trace'
        M           = $script:Text
        TraceZero     = 0
        TraceFF        = 0
        TraceData      = 0
        TraceCount       = 0
        TraceEntropy       = 0.0
    })
    Set-UiLock $true
    $txtStatus.Foreground = $script:Theme.ACCENT
    $prgProgress.Value = 0
    $txtPercent.Text = ''; $txtSpeed.Text = ''; $txtRemain.Text = ''
    $script:lastByte = 0L; $script:lastTime = Get-Date
    Add-LogEntry ((T 'trace_started_log') -f [int]$selection.Number)
    Start-Worker $traceScript
})

# ---- Surface test (bad sectors, read-only, runspace) ----------------------
$btnSurface.Add_Click({
    $selection = $lstDisks.SelectedItem
    if ($null -eq $selection) {
        [System.Windows.MessageBox]::Show((T 'first_disk_select'), 'Strix Disk Cleaner', 'OK', 'Information') | Out-Null
        return
    }
    $answer = [System.Windows.MessageBox]::Show(((T 'surface_question') -f $selection.Size), (T 'surface_title'), 'YesNo', 'Question')
    if ($answer -ne 'Yes') { return }

    $script:sync = [hashtable]::Synchronized(@{
        DiskNo      = $selection.Number
        Model       = $selection.Model
        SizeBytes      = $selection.SizeBytes
        TotalBytes  = [long]$selection.SizeBytes
        DoneBytes   = 0L
        Status       = 'Starting...'
        Pass       = ''
        Record       = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
        Cancel       = $false
        Done       = $false
        Error        = $null
        Mod         = 'surface'
        M           = $script:Text
        BadCount    = 0
        BadOffsets = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    })
    Set-UiLock $true
    $txtStatus.Foreground = $script:Theme.ACCENT
    $prgProgress.Value = 0
    $script:lastByte = 0L; $script:lastTime = Get-Date
    Add-LogEntry ((T 'surface_started_log') -f $selection.Number, $selection.Model)
    Start-Worker $surfaceScript
})

# ---- SECURE WIPE: multi-select -> queue ------------------------------------
$btnWipe.Add_Click({
    $selectedItems = @($lstDisks.SelectedItems)
    if ($selectedItems.Count -eq 0) {
        [System.Windows.MessageBox]::Show((T 'first_disk_select'), 'Strix Disk Cleaner', 'OK', 'Information') | Out-Null
        return
    }
    $method = Get-WipeMethod

    # Protection check for all selections (if any is blocked, abort entirely)
    foreach ($pick in $selectedItems) {
        $blocked = Test-SafetyWall $pick.Number $pick.Serial
        if ($blocked) {
            Add-LogEntry ((T 'protect_block_log') -f $blocked)
            [System.Windows.MessageBox]::Show(
                ((T 'protect_block_msg') -f $blocked),
                (T 'protect_block_title'), 'OK', 'Stop') | Out-Null
            return
        }
    }

    # Summary
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine(((T 'summary_start') -f $selectedItems.Count))
    [void]$sb.AppendLine('')
    $hiddenExists = $false
    foreach ($pick in $selectedItems) {
        [void]$sb.AppendLine(((T 'summary_disk') -f $pick.Number, $pick.Model, $pick.Size, $pick.Type, $pick.Bus, $pick.Serial))
        $g = Get-HiddenArea ([int]$pick.Number) $pick.Bus
        if ($g.Present) {
            $hiddenExists = $true
            [void]$sb.AppendLine('      [!] ' + ((T 'hpa_present') -f (Format-Size $g.HiddenBytes), ($g.NativeSector - $g.UserSector)))
        }
    }
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine(((T 'summary_method') -f $method.Name))
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine((T 'summary_final'))
    # If a hidden area (HPA/DCO) exists, use the more attention-grabbing Stop icon
    $summaryIcon = if ($hiddenExists) { 'Stop' } else { 'Warning' }
    $answer = [System.Windows.MessageBox]::Show($sb.ToString(), (T 'final_warning_title'), 'YesNo', $summaryIcon)
    if ($answer -ne 'Yes') { return }

    # Typed confirmation
    $confirmTemplate = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="{T:confirm_title}" Width="470" Height="220" WindowStartupLocation="CenterOwner"
        Background="%BG%" ResizeMode="NoResize">
  <StackPanel Margin="18">
    <TextBlock Foreground="%FG%" TextWrapping="Wrap" FontSize="13" Text="{T:confirm_text}"/>
    <TextBox Name="txtConfirm" Margin="0,14,0,0" FontSize="16" Padding="6"
             Background="%PANEL%" Foreground="%FG%" BorderBrush="%BORDER%"/>
    <StackPanel Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,16,0,0">
      <Button Name="btnBack" Content="{T:btn_back}" Padding="16,7" Margin="0,0,10,0"/>
      <Button Name="btnContinue" Content="{T:btn_startwipe}" Padding="16,7" Background="%RED%" Foreground="White" FontWeight="Bold" IsEnabled="False"/>
    </StackPanel>
  </StackPanel>
</Window>
'@
    $confirmXaml = Expand-Xaml $confirmTemplate
    $confirmReader = New-Object System.Xml.XmlNodeReader $confirmXaml
    $confirmWindow = [Windows.Markup.XamlReader]::Load($confirmReader)
    $confirmWindow.Owner = $window
    if ($script:AppIcon) { $confirmWindow.Icon = $script:AppIcon }
    $txtConfirm   = $confirmWindow.FindName('txtConfirm')
    $btnContinue  = $confirmWindow.FindName('btnContinue')
    $btnAbort = $confirmWindow.FindName('btnBack')
    $txtConfirm.Add_TextChanged({ $btnContinue.IsEnabled = ($txtConfirm.Text -ceq 'ERASE') }.GetNewClosure())
    $btnContinue.Add_Click({ $confirmWindow.DialogResult = $true; $confirmWindow.Close() }.GetNewClosure())
    $btnAbort.Add_Click({ $confirmWindow.DialogResult = $false; $confirmWindow.Close() }.GetNewClosure())
    $result = $confirmWindow.ShowDialog()
    if ($result -ne $true) { Add-LogEntry (T 'confirm_none_log'); return }

    # Enqueue and start
    $script:queue.Clear()
    $script:reportPaths.Clear()
    $script:toEject.Clear()
    $script:wipedCount = 0
    $script:taskbarOn  = [bool]$chkTaskbar.IsChecked
    $script:taskbarEject = [bool]$chkEject.IsChecked
    if ($script:taskbarOn) { Set-TaskbarProgress 'Normal' }
    foreach ($pick in $selectedItems) {
        $script:queue.Enqueue($pick)
        # Add USB disks to the eject-when-done list
        if ($script:taskbarEject -and $pick.Bus -eq 'USB') { $script:toEject.Add([int]$pick.Number) }
    }
    if ($script:queue.Count -gt 1) { Add-LogEntry ((T 'queue_log') -f $script:queue.Count) }

    $first = $script:queue.Dequeue()
    if (-not (Start-Wipe $first)) { Step-Queue | Out-Null }
})

# ---- Change language (live re-translation, no restart) --------------------------
$cmbLanguage.Add_SelectionChanged({
    if (-not $script:uiReady) { return }
    $idx = $cmbLanguage.SelectedIndex
    if ($idx -lt 0 -or $idx -ge $script:LangCodes.Count) { return }
    $newCode = [string]$script:LangCodes[$idx]
    if ($newCode -eq [string]$script:Settings.Language) { return }
    if ($null -ne $script:sync) {                       # busy: block and revert the selection
        [System.Windows.MessageBox]::Show((T 'busy_msg'), 'Strix Disk Cleaner', 'OK', 'Information') | Out-Null
        $script:uiReady = $false
        $cmbLanguage.SelectedIndex = [array]::IndexOf($script:LangCodes, [string]$script:Settings.Language)
        $script:uiReady = $true
        return
    }
    if (-not $script:Languages.ContainsKey($newCode)) { return }
    $script:Settings.Language = $newCode
    $script:Text = $script:Languages[$newCode]
    Save-Settings
    Update-UiText
})

# ---- Change theme (restarts) ------------------------------
$cmbTheme.Add_SelectionChanged({
    if (-not $script:uiReady) { return }
    if ($null -ne $script:sync) {
        [System.Windows.MessageBox]::Show((T 'busy_msg'), 'Strix Disk Cleaner', 'OK', 'Information') | Out-Null
        $script:uiReady = $false
        $cmbTheme.SelectedIndex = $(if ($script:Settings.Theme -eq 'light') { 1 } else { 0 })
        $script:uiReady = $true
        return
    }
    $answer = [System.Windows.MessageBox]::Show((T 'theme_dil_question'), (T 'theme_dil_title'), 'YesNo', 'Question')
    if ($answer -ne 'Yes') {
        $script:uiReady = $false
        $cmbTheme.SelectedIndex = $(if ($script:Settings.Theme -eq 'light') { 1 } else { 0 })
        $script:uiReady = $true
        return
    }
    $script:Settings.Theme = $(if ($cmbTheme.SelectedIndex -eq 1) { 'light' } else { 'dark' })
    Get-CurrentSettings
    Save-Settings
    # Relaunch via the ABSOLUTE System32 path (never bare "powershell"): this runs
    # from an already-elevated process, so a bare name would let a HKCU App Paths
    # redirect or a CWD-planted powershell.exe execute elevated with no UAC prompt.
    $psExe = Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell\v1.0\powershell.exe'
    Start-Process -FilePath $psExe -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-WindowStyle','Hidden','-File',"`"$PSCommandPath`"" -WindowStyle Hidden
    $window.Close()
})

# ---- Collect / save settings -----------------------------------------------
function Get-CurrentSettings {
    $script:Settings.MethodIdx   = [int]$cmbMethod.SelectedIndex
    $script:Settings.Verify     = [bool]$chkVerify.IsChecked
    $script:Settings.Format = [bool]$chkFormat.IsChecked
    $script:Settings.Report       = [bool]$chkReport.IsChecked
    $script:Settings.Pdf         = [bool]$chkPdf.IsChecked
    $script:Settings.Sound         = [bool]$chkSound.IsChecked
    $script:Settings.Eject       = [bool]$chkEject.IsChecked
    $script:Settings.Taskbar = [bool]$chkTaskbar.IsChecked
}
$window.Add_Closing({ Get-CurrentSettings; Save-Settings })

# ============================ START =======================================
# Apply saved settings to the UI
$yi = [int]$script:Settings.MethodIdx
if ($yi -ge 0 -and $yi -le 3) { $cmbMethod.SelectedIndex = $yi }
$chkVerify.IsChecked     = [bool]$script:Settings.Verify
$chkFormat.IsChecked = [bool]$script:Settings.Format
$chkReport.IsChecked       = [bool]$script:Settings.Report
$chkPdf.IsChecked         = [bool]$script:Settings.Pdf
$chkSound.IsChecked         = [bool]$script:Settings.Sound
$chkEject.IsChecked       = [bool]$script:Settings.Eject
$chkTaskbar.IsChecked       = [bool]$script:Settings.Taskbar
$txtReportFolder.Text      = (Get-ReportFolder)
$cmbTheme.SelectedIndex    = $(if ($script:Settings.Theme -eq 'light') { 1 } else { 0 })

# Language dropdown: native names in the fixed suite order, select the active one.
# (Runs while $script:uiReady is still $false, so this does not fire a live switch.)
foreach ($code in $script:LangCodes) {
    $nm = if ($script:LangNames.ContainsKey($code)) { $script:LangNames[$code] } else { $code }
    [void]$cmbLanguage.Items.Add($nm)
}
$langIdx = [array]::IndexOf($script:LangCodes, [string]$script:Settings.Language)
if ($langIdx -lt 0) { $langIdx = 0 }
$cmbLanguage.SelectedIndex = $langIdx
Update-UiText                       # initial re-translation pass after the window loads

Update-DiskList
Add-LogEntry (T 'ready_log')
Add-LogEntry ((T 'protect_log') -f $env:SystemDrive)
$script:uiReady = $true
[void]$window.ShowDialog()

# ---- Cleanup on exit: release the single-instance mutex -----------------
if ($null -ne $script:singleInstance) {
    try { if ($script:singleInstanceNew) { $script:singleInstance.ReleaseMutex() } } catch { }
    try { $script:singleInstance.Dispose() } catch { }
}
