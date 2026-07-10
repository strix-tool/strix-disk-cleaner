# Making Strix Disk Cleaner a real, safely-installable Windows program

This folder turns the app into a proper installer (Program Files install, Start
Menu / Desktop shortcuts, an entry in **Apps & features**, a clean uninstaller)
— and sets up the one thing that actually makes a Windows program "install
safely": **code signing**.

Read this once before you build. The honest summary up front:

> A Windows program installs "safely" (no *Unknown Publisher* warning, no
> antivirus false positive) when it is **signed with a code-signing certificate
> from a trusted CA** *and* has accumulated **SmartScreen reputation**. There is
> no way to package your way around this — signing is the linchpin, not the
> installer format. Everything below is built around that fact.

---

## The three layers of "safe to install"

1. **Transparent packaging (done).** No opaque `.exe` that drops an embedded
   payload and runs hidden PowerShell. That packaging is exactly what tripped
   `Trojan:Win32/Wacatac.B!ml`. The default here ships the readable `.ps1` and
   launches it directly. This alone removes the reported detection.

2. **A real installer (this folder).** `StrixDiskCleaner.iss` (Inno Setup)
   produces a normal Windows setup: installs to Program Files, makes shortcuts
   with your icon, and registers a proper uninstaller. This makes it *a program*.

3. **Code signing + reputation (only you can do this).** The signed installer
   carries your verified publisher name and, over time, earns SmartScreen
   reputation so users stop seeing warnings. This is the part that costs money
   and identity verification — see below.

---

## What's already built

`StrixDiskCleaner-Setup-2.3.0.exe` (in the package root and in
`installer\dist\`) is a **ready, working next-next-next wizard installer**. It
installs a **no-console launcher** (`StrixDiskCleaner.exe`) that opens the app
with no PowerShell window. It is **unsigned**, so it works for testing but will
show a SmartScreen "unknown publisher" warning until you sign it (below).

## Rebuild pipeline

Prerequisites (install once on a Windows build machine):
- **NSIS 3.x** — https://nsis.sourceforge.io/Download (provides `makensis.exe`)
- **.NET Framework 4.x** — ships with Windows 10/11 (provides `csc.exe` for the launcher)
- **Windows SDK** (provides `signtool.exe`) — only needed if you sign

Commands (run from `installer\`):

```powershell
# Rebuild launcher + wizard, UNSIGNED (testing only — shows SmartScreen warning)
.\Build-Setup.ps1

# Signed build with a certificate on a USB token / HSM:
.\Build-Setup.ps1 -Sign -Thumbprint 'YOUR_CERT_SHA1_THUMBPRINT'

# Signed build with Microsoft Trusted Signing (cloud, no token):
.\Build-Setup.ps1 -Sign -TrustedSigning -Metadata .\trusted-signing.json
```

`Build-Setup.ps1` (1) compiles the no-console launcher with `csc`, (2) signs it
if `-Sign`, (3) compiles the NSIS wizard, (4) signs the installer. The output
lands in `installer\dist\StrixDiskCleaner-Setup-2.3.0.exe`.

Sign **both** the launcher and the installer — SmartScreen and Defender evaluate
each PE file, and reputation is tied to your signing identity. `Build-Setup.ps1`
with `-Sign` does both for you.

> The installer is NSIS-based. If you prefer Inno Setup instead, the same
> shortcuts/registry layout ports directly; NSIS is used here because it builds
> a real Windows installer even from a non-Windows CI box.

---

## Code signing in 2026 — what actually applies now

The rules changed recently, so ignore older tutorials:

- **Certificates must live on hardware.** Since **June 2023**, every OV/EV
  code-signing certificate's private key must sit on a **FIPS-validated USB
  token or a cloud HSM** — file-based `.pfx` certs are no longer issued.
- **EV no longer buys an instant SmartScreen pass.** Microsoft removed EV's
  automatic first-download reputation in **2024**. EV and OV now build
  reputation the same way — through clean download volume. So **don't pay the EV
  premium just to skip warnings**; it won't.
- **Even a correctly signed brand-new build can still show a SmartScreen prompt**
  until its publisher/file reputation builds. Reputation is tied to your signing
  identity, so **sign every release with the same certificate** and it
  accumulates.

### Your realistic options (cheapest first)

| Option | Cost | Hardware token? | Notes |
|---|---|---|---|
| **Microsoft Trusted Signing** | ~$10/month | No (cloud HSM) | Cheapest, CI-friendly. **Availability is regional** — orgs in US/CA/EU/UK; individuals in US/CA only. If you're outside these, use an OV cert. |
| **OV certificate** (DigiCert, Sectigo, GlobalSign, SSL.com…) | ~$200–400/yr | Yes (USB token or cloud HSM) | Works worldwide. Puts your verified org name on the installer. |
| **IV / Sole-proprietor cert** | ~$100–250/yr | Yes | For individuals without a registered company. |
| **EV certificate** | ~$400+/yr | Yes | Only worth it for enterprise procurement or kernel-driver signing — **not** needed here. |

> Note: Microsoft Trusted Signing availability is regional (for example, it is not
> offered in some countries such as Turkey). If it isn't available to you, an
> **OV certificate on a USB token** from a CA like Sectigo/DigiCert/SSL.com is the
> practical path. Budget for the cert **plus** a one-time token/shipping fee.

### The signing command (what `sign.ps1` runs)

```powershell
signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 `
    /sha1 <THUMBPRINT_ON_TOKEN> StrixDiskCleaner-Setup-2.3.0.exe
```

Always `/tr` (timestamp): a timestamped signature stays valid even after the
certificate expires. Sign the installer; if you also ship the native launcher
`.exe`, sign that **before** compiling the installer.

---

## The one path to ZERO warnings from day one

If you ever want no SmartScreen prompt at all on first download, the **Microsoft
Store (MSIX)** is the only route: Microsoft re-signs Store packages, so users
never see a warning and you don't buy a certificate. Caveat: a tool that does
raw full-disk destruction and requires admin may not pass Store certification
policy — worth checking before committing to that path. For direct download
distribution, signed + reputation is the ceiling.

---

## After you sign — kill the false positive for good

1. Upload the signed installer to **VirusTotal** to confirm it's clean across
   engines.
2. If Defender still flags it early, submit it once at
   <https://www.microsoft.com/wdsi/filesubmission> → *Software developer →
   false positive*. Reputation + that submission resolves it.

---

## If you have no budget for a certificate

Then you cannot make it "install with no warning" — that's just how Windows
works now. The unsigned wizard here still works; users will simply see a
SmartScreen "unknown publisher" prompt on first run and must choose
**More info -> Run anyway**. Tell them that upfront and only if they trust the
source. If you'd rather avoid shipping any `.exe` at all, distribute
`StrixDiskCleaner.ps1` plus `Debug-Run.cmd` and let users run the script
directly (there will be a brief console). Either way: don't tell users to
disable Defender.
