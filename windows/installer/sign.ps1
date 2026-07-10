# ============================================================================
#  sign.ps1  -  Authenticode signing helper for Strix Disk Cleaner
#
#  Signing is the single most important step for "installs safely on Windows":
#  it attaches your verified publisher identity, removes the "Unknown Publisher"
#  UAC/SmartScreen wording, and is what stops the Defender ML false positive
#  from recurring. This wraps signtool.exe for the two realistic 2026 setups.
#
#  USAGE
#    # A) Traditional OV/EV certificate on a USB token / HSM (thumbprint):
#    .\sign.ps1 -File .\dist\StrixDiskCleaner-Setup-2.3.0.exe `
#               -Thumbprint 'AB12...CD' 
#
#    # B) Microsoft Trusted Signing (cloud, no hardware token) via dlib metadata:
#    .\sign.ps1 -File .\dist\StrixDiskCleaner-Setup-2.3.0.exe `
#               -TrustedSigning -Metadata .\trusted-signing.json
#
#  Requirements: Windows SDK signtool.exe on PATH (or pass -SignTool).
#  Always timestamps, so signatures stay valid after the certificate expires.
# ============================================================================
[CmdletBinding(DefaultParameterSetName = 'Thumbprint')]
param(
    [Parameter(Mandatory)] [string[]] $File,

    [Parameter(ParameterSetName = 'Thumbprint', Mandatory)]
    [string] $Thumbprint,

    [Parameter(ParameterSetName = 'TrustedSigning', Mandatory)]
    [switch] $TrustedSigning,
    [Parameter(ParameterSetName = 'TrustedSigning', Mandatory)]
    [string] $Metadata,           # dlib metadata json (endpoint, account, profile)

    [string] $SignTool = 'signtool.exe',
    [string] $TimestampUrl = 'http://timestamp.digicert.com'
)

$ErrorActionPreference = 'Stop'

function Resolve-SignTool {
    param([string] $Name)
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    # common Windows SDK locations
    $roots = @("${env:ProgramFiles(x86)}\Windows Kits\10\bin",
               "${env:ProgramFiles}\Windows Kits\10\bin")
    foreach ($r in $roots) {
        if (Test-Path $r) {
            $hit = Get-ChildItem $r -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
                   Where-Object { $_.FullName -match '\\x64\\' } |
                   Sort-Object FullName -Descending | Select-Object -First 1
            if ($hit) { return $hit.FullName }
        }
    }
    throw "signtool.exe not found. Install the Windows SDK or pass -SignTool."
}

$tool = Resolve-SignTool -Name $SignTool
Write-Host "signtool: $tool"

foreach ($f in $File) {
    if (-not (Test-Path $f)) { throw "File not found: $f" }
    Write-Host "Signing: $f"

    if ($PSCmdlet.ParameterSetName -eq 'TrustedSigning') {
        # Trusted Signing uses the Azure dlib provider + a metadata json.
        & $tool sign /v /debug /fd SHA256 `
            /tr $TimestampUrl /td SHA256 `
            /dlib "Azure.CodeSigning.Dlib.dll" `
            /dmdf $Metadata `
            $f
    }
    else {
        # Certificate on a hardware token / HSM, selected by SHA-1 thumbprint.
        & $tool sign /v /fd SHA256 `
            /tr $TimestampUrl /td SHA256 `
            /sha1 $Thumbprint `
            $f
    }
    if ($LASTEXITCODE -ne 0) { throw "signtool failed on $f (exit $LASTEXITCODE)" }

    # Verify the signature chains and is timestamped.
    & $tool verify /pa /v $f | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "signature verification failed on $f" }
    Write-Host "OK: $f is signed and verified.`n"
}
