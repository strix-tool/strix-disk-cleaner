# Strix Disk Cleaner (Windows) — v2.3

## Install it (recommended)

**Double-click `StrixDiskCleaner-Setup-2.3.0.exe`** and click through the wizard
(Next -> Next -> Install). It installs into Program Files, creates Start Menu and
Desktop shortcuts with the app icon, and adds an entry to **Apps & features** so
you can uninstall it the normal way.

When you launch the app, **no PowerShell console appears** — it opens straight to
the application window. You get a single Administrator (UAC) prompt, because
wiping raw disks needs admin rights.

> **First-run warning is expected.** This installer is **not code-signed yet**,
> so Windows SmartScreen will show *"Windows protected your PC / unknown
> publisher."* Click **More info -> Run anyway** to proceed. To remove that
> warning for good, sign the build — see `installer\README-PACKAGING.md`.

## Or run it without installing (portable)

**Double-click `StrixDiskCleaner.exe`** — the same no-console launcher, no
install required. It runs the app straight from the folder.

## Uninstall

Use **Apps & features -> Strix Disk Cleaner -> Uninstall**, or the *Uninstall*
shortcut in the Start Menu folder. (Portable use: just delete the folder.)

## Troubleshooting

If the app doesn't start, run **`Debug-Run.cmd`** — it launches the script in a
visible window so any error stays on screen (also logged to
`%TEMP%\StrixDiskCleaner_error.log`).

---

## How the "no console" works (and why the old .exe was flagged)

The old build wrapped the script in an `.exe` that **embedded** the script,
**dropped it to disk**, verified it, and ran a **hidden PowerShell** child. That
"drop a payload + run hidden shell" shape, unsigned, is what Defender's ML
classifier flagged as `Trojan:Win32/Wacatac.B!ml` (a false positive).

This build fixes it two ways:

1. **A minimal launcher.** `StrixDiskCleaner.exe` is a tiny GUI-subsystem program
   that just starts the *already-installed* `StrixDiskCleaner.ps1` with no
   console window. It embeds nothing and drops nothing — a far cleaner artifact.
2. **The console is gone at every stage.** The launcher runs PowerShell with
   `CreateNoWindow`, and the script's own elevation/restart paths were changed to
   run hidden, so no console flashes even on the fallback paths.

The application code (`StrixDiskCleaner.ps1`) is unchanged apart from those two
one-line "run hidden" tweaks — same Protection Shield, same wipe methods.

## The one remaining step (only you can do it)

Removing the flagged packaging stops the specific detection, but for a **truly
warning-free install** (no SmartScreen "unknown publisher", no early
false-positive), the build must be **code-signed**. That needs a certificate and
identity verification — it can't be done by repackaging. The full, current
(2026) guidance and the build/sign pipeline are in
installer\README-PACKAGING.md.
