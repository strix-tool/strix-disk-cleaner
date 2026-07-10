# Security & Safety Policy — Strix Disk Cleaner

## Reporting a vulnerability

Report privately via GitHub Security Advisories (the repo's **Security** tab) or the
[Strix Advanced Tools](https://github.com/strix-tool) maintainer contacts — not a public issue.

## This is a destructive tool

Strix Disk Cleaner **permanently destroys data**. The security work here is mostly about
**preventing the wrong disk from being erased**, and being honest about what erasure
guarantees on modern hardware.

## Protection shield

### Windows (`StrixDiskCleaner.ps1`)
Five layers so the system/boot disk can never be targeted: the protected set is computed
from `IsBoot`/`IsSystem`/the system-drive-letter (by disk number **and** serial),
protected disks are hidden from the list, and a deep re-validation (`Assert-DiskProtection`)
re-queries the disk and re-checks boot/system/serial/size **before every destructive
step** — defeating device-renumbering / TOCTOU. A typed `ERASE` confirmation is required.

### Linux (`strixwipe`)
The decision logic is a **pure, unit-tested** module (`strix_disk_cleaner_core.py`):
- `protection_check()` refuses a disk if **any** of its partitions is mounted, or if it
  backs the root (`/`) filesystem. Partitions are normalised to the whole disk, so
  mounting `/dev/sda1` protects all of `/dev/sda`.
- The eraser additionally requires **root**, a typed device path **and** the word `ERASE`,
  the `--yes-really-erase` flag, and it **re-runs the check immediately before writing**.
- `tests/test_safety.py` asserts the shield refuses the root disk, mounted disks, and
  mounted partitions, and allows only unmounted data/loopback devices.

## Hardening (both platforms)

- **No shell / no `Invoke-Expression`.** External tools are called with argument lists.
- **Cryptographic RNG** for the random overwrite pass (`RandomNumberGenerator` on Windows,
  `os.urandom` on Linux).
- **Absolute-path elevation.** The Windows self-elevation uses the full
  `System32\WindowsPowerShell\v1.0\powershell.exe` path (not a bare name), so a hijacked
  `%PATH%` cannot substitute a rogue `powershell.exe`.
- **No network.** Certificate verification is offline (SHA-256).

## Erasure guarantees (be honest)

- Overwriting reaches the **Clear** level (NIST SP 800-88). It is reliable on **HDDs**.
- On **SSD/NVMe/flash**, wear levelling means an overwrite may leave data in spare blocks.
  Prefer a **hardware sanitize**: `blkdiscard`, `nvme sanitize`, or ATA Secure Erase
  (`hdparm`). The tool warns and steers you to these on flash devices.
- Hidden areas (HPA/DCO) and remapped sectors may not be reachable by overwrite; hardware
  sanitize handles them.

## Testing

Always rehearse on a **loopback device** (`losetup`) before touching real hardware — see
the README. Never run destructive tests in CI against anything but a loopback file.
