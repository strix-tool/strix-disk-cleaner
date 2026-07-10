# ============================================================================
#  Build-I18n.ps1  -  regenerate the inline translation data in StrixDiskCleaner.ps1
#
#  Single source of truth: ..\..\i18n\<code>.json  (English source string -> translation;
#  en.json is the pass-through English source). This tool:
#    1. extracts the English key -> source-string map from the $script:Languages.en
#       hashtable in the .ps1 (that map binds the app's stable short keys to English),
#    2. reads each i18n\<code>.json and, per short key, looks up the translation of the
#       English source string (falling back to English when absent/identical),
#    3. writes the result BETWEEN the <I18N-DATA-START>/<I18N-DATA-END> markers as a
#       single-quoted here-string of \uXXXX-escaped JSON (keeps the .ps1 pure ASCII so
#       Windows PowerShell 5.1 reads it correctly without a BOM),
#    4. refreshes the native-name dropdown map ($script:LangNamesJson), also \uXXXX.
#
#  Run on Windows after editing any i18n\<code>.json. No arguments.
# ============================================================================
$ErrorActionPreference = 'Stop'
$build = $PSScriptRoot
$root  = Split-Path $build -Parent                 # ...\windows
$repo  = Split-Path $root  -Parent                 # ...\strix-disk-cleaner
$ps1   = Join-Path $root 'StrixDiskCleaner.ps1'
$i18n  = Join-Path $repo 'i18n'
$codes = @('de','fr','es','it','pt-BR','pl','uk','ru','sv','zh-CN','ja','ko')

$textAll = [System.IO.File]::ReadAllText($ps1, [System.Text.Encoding]::UTF8)
$lines   = [System.IO.File]::ReadAllLines($ps1, [System.Text.Encoding]::UTF8)

# --- 1) extract $script:Languages.en (short key -> English source string) ----------
$startIdx = ($lines | Select-String -SimpleMatch 'en = @{' | Select-Object -First 1).LineNumber
if (-not $startIdx) { throw 'Could not find "en = @{" in the script.' }
$startIdx--                                          # to 0-based index of the "en = @{" line
$closeIdx = -1
for ($i = $startIdx + 1; $i -lt $lines.Length; $i++) { if ($lines[$i].Trim() -eq '}') { $closeIdx = $i; break } }
if ($closeIdx -lt 0) { throw 'Could not find the closing brace of the en block.' }
$inner = $lines[($startIdx + 1)..($closeIdx - 1)]
$en = Invoke-Expression ("[ordered]@{`r`n" + ($inner -join "`r`n") + "`r`n}")
Write-Host ("English keys extracted: {0}" -f $en.Count)

# --- 2) build the per-language short-key -> translation objects ---------------------
function ConvertTo-AsciiEscaped([string]$s) {
    # Force every non-ASCII char to a \uXXXX escape so the emitted JSON is pure ASCII
    # (Windows PowerShell 5.1 reads an ASCII .ps1 correctly even without a BOM).
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $s.ToCharArray()) {
        $code = [int]$ch
        if ($code -gt 127) { [void]$sb.Append('\u'); [void]$sb.Append($code.ToString('x4')) }
        else { [void]$sb.Append($ch) }
    }
    return $sb.ToString()
}
function Escape-ToAsciiJson($obj) {
    return (ConvertTo-AsciiEscaped ($obj | ConvertTo-Json -Compress -Depth 4))
}

$blobLines = New-Object System.Collections.Generic.List[string]
$blobLines.Add('{')
for ($ci = 0; $ci -lt $codes.Count; $ci++) {
    $code = $codes[$ci]
    $file = Join-Path $i18n ($code + '.json')
    if (-not (Test-Path $file)) { throw "Missing translation file: $file" }
    $j = Get-Content $file -Raw -Encoding UTF8 | ConvertFrom-Json
    $tr = @{}
    foreach ($p in $j.PSObject.Properties) { $tr[$p.Name] = [string]$p.Value }

    $obj = [ordered]@{}
    $included = 0
    foreach ($k in $en.Keys) {
        $eng = [string]$en[$k]
        $val = $null
        if ($tr.ContainsKey($eng)) { $val = [string]$tr[$eng] }
        if ($null -ne $val -and $val.Length -gt 0 -and $val -cne $eng) { $obj[$k] = $val; $included++ }
    }
    $comma = if ($ci -lt $codes.Count - 1) { ',' } else { '' }
    $blobLines.Add(('"{0}":{1}{2}' -f $code, (Escape-ToAsciiJson $obj), $comma))
    Write-Host ("  {0,-6} translated keys embedded: {1}" -f $code, $included)
}
$blobLines.Add('}')
$blob = ($blobLines -join "`r`n")

# --- 3) refresh the native-name map, \uXXXX-escaped --------------------------------
$namesMarker = '$script:LangNamesJson = @' + "'"
$np = $textAll.IndexOf($namesMarker)
if ($np -lt 0) { throw 'LangNamesJson marker not found.' }
$nAfter = $textAll.IndexOf("`n", $np) + 1
$nClose = $textAll.IndexOf("'@", $nAfter)
$namesRaw = $textAll.Substring($nAfter, $nClose - $nAfter).Trim()
$namesObj = $namesRaw | ConvertFrom-Json
$namesAscii = ConvertTo-AsciiEscaped ($namesObj | ConvertTo-Json -Compress -Depth 3)

# --- 4) splice both regions back into the file ------------------------------------
function Splice-HereString([string]$text, [string]$marker, [string]$content) {
    $p = $text.IndexOf($marker)
    if ($p -lt 0) { throw "Marker not found: $marker" }
    $after = $text.IndexOf("`n", $p) + 1
    $close = $text.IndexOf("'@", $after)
    if ($close -lt 0) { throw "Closing '@ not found after marker: $marker" }
    return $text.Substring(0, $after) + $content + "`r`n" + $text.Substring($close)
}
function Replace-Between([string]$text, [string]$startM, [string]$endM, [string]$inner) {
    $s = $text.IndexOf($startM); if ($s -lt 0) { throw "start marker missing: $startM" }
    $sEnd = $text.IndexOf("`n", $s) + 1
    $e = $text.IndexOf($endM, $sEnd); if ($e -lt 0) { throw "end marker missing: $endM" }
    return $text.Substring(0, $sEnd) + $inner + $text.Substring($e)
}

# names first (content has no '@), then the blob via robust START/END markers
$textAll = Splice-HereString $textAll $namesMarker $namesAscii
$hereBlock = "`$script:I18nData = @'`r`n" + $blob + "`r`n'@`r`n"
$textAll = Replace-Between $textAll '# <I18N-DATA-START>' '# <I18N-DATA-END>' $hereBlock

# Write pure-ASCII UTF-8 (no BOM); content is ASCII-only after escaping.
$enc = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($ps1, $textAll, $enc)

$bytes = [System.IO.File]::ReadAllBytes($ps1)
$nonAscii = ($bytes | Where-Object { $_ -gt 127 }).Count
Write-Host ("Blob size: {0} bytes" -f $blob.Length)
Write-Host ("Wrote {0}; non-ASCII bytes now: {1}  (BOM: {2})" -f $ps1, $nonAscii, ($bytes[0] -eq 0xEF))
