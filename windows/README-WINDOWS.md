# Strix Disk Cleaner — Windows

Secure, irreversible disk wiping to **NIST SP 800-88** and **DoD 5220.22-M**, with a
signed data-destruction certificate. Runs fully offline — no telemetry, no accounts.

## Running it

- Launch **Strix Disk Cleaner** from the Start Menu (or the Desktop shortcut).
- Wiping a disk requires administrator rights, so Windows shows a single UAC prompt.
- The interface is available in 13 languages and follows your Windows display
  language automatically; you can also switch it from the Language selector.

## Safety

The disk holding Windows — and every boot/system disk — is **hidden and can never be
selected**. A five-layer protection shield re-validates the target (disk number,
serial, size, boot/system flags and the active pagefile) immediately before every
destructive write. To start a wipe you must type the word **ERASE** exactly.

> A wipe permanently destroys all data on the selected disk and cannot be undone.
> Double-check the disk, model and serial before you confirm.

## Verify your download

Every GitHub release ships a `SHA256SUMS` file. Compare it against your download:

```powershell
Get-FileHash .\StrixDiskCleaner-Setup-*.exe -Algorithm SHA256
```

Builds are not code-signed yet, so Windows SmartScreen may warn on first run — choose
**More info → Run anyway**, or verify the checksum first. Never disable your antivirus.

## More

- Full documentation, threat model and Linux instructions are in the repository.
- Report a security issue privately via the repository's `SECURITY.md`.
