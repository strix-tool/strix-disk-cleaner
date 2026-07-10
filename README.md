
# Strix Disk Cleaner

> **Securely and irreversibly erase an entire disk** — with a multi-layer safety shield
> that makes it *impossible* to wipe your system disk by mistake. Targets NIST SP 800-88
> and DoD 5220.22-M. Offline, no telemetry.

[![License: MIT](https://img.shields.io/badge/License-MIT-informational.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-blue.svg)](#installation)
[![Safety](https://img.shields.io/badge/safety-shield%20%2B%20tests-success.svg)](SECURITY.md)

> ⚠️ **This tool destroys data permanently and cannot be undone.** Read the safety
> section before use. Always double-check the target device.

Part of the open-source **[Strix Advanced Tools](https://github.com/strix-tools)** suite.

## Editions

- **Windows** — a WPF GUI (`StrixDiskCleaner.ps1`) with a **5-layer protection shield**,
  hardware-capability detection (NVMe/ATA/TCG-Opal, hidden HPA/DCO areas), SMART health,
  post-wipe repartition/format/TRIM, and a printable destruction certificate.
- **Linux** — `strixwipe`, a command-line eraser built on the same safety philosophy: a
  **pure, unit-tested protection shield** that refuses the root disk and any mounted disk,
  hardware sanitize (`blkdiscard` / `nvme sanitize` / `hdparm`) or multi-pass overwrite,
  and a typed-confirmation gauntlet. CLI-only by design — never one accidental click away.

## Safety model

- **The system disk can never be selected.** On both platforms the disk holding the OS /
  root filesystem is detected and excluded. On Linux, **any** disk with a mounted
  partition is refused (unmount it first).
- **Typed confirmation.** You must type the exact device path and the word `ERASE`, and
  (Linux) pass `--yes-really-erase`. There is a re-check immediately before writing
  (defeats device-renumbering / TOCTOU).
- **SSD honesty.** On flash, overwriting is unreliable (wear levelling); the tool steers
  you to hardware sanitize (`blkdiscard` / `nvme sanitize`) instead.

## Installation

### Windows

Install with the setup wizard (`StrixDiskCleaner-Setup-*.exe` from Releases) or run the
script directly. A single UAC prompt is required (raw disk access needs admin). Details
and the signing story: [docs/install-windows.md](docs/install-windows.md) and
[windows/installer/README-PACKAGING.md](windows/installer/README-PACKAGING.md).

### Linux (Ubuntu / Debian)

```bash
sudo apt install ./strix-disk-cleaner_1.0.0_all.deb   # from Releases
# or from source:
sudo ./linux/install.sh

strixwipe list                                         # safe: list disks + erasable state
sudo strixwipe info /dev/sdX
sudo strixwipe erase /dev/sdX --method blkdiscard --yes-really-erase
```

**Test it safely on a loopback device first** (no real disk touched):

```bash
truncate -s 256M /tmp/t.img
sudo losetup -f --show /tmp/t.img          # e.g. /dev/loop0
sudo strixwipe erase /dev/loop0 --method zero --yes-really-erase
sudo losetup -d /dev/loop0
```

See [docs/usage-linux.md](docs/usage-linux.md).

## Security & safety

Full threat model, the protection-shield details, and the erase-method guidance are in
**[SECURITY.md](SECURITY.md)**. The Linux safety shield is covered by unit tests
(`tests/test_safety.py`) that assert it refuses the root/mounted disks.

## License

[MIT](LICENSE) © 2026 Strix Advanced Tools. Use only on disks you own. You are responsible for
what you erase.
