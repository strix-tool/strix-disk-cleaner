# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/); versioning: [SemVer](https://semver.org/).

## [Unreleased]

### Added
- **Native Linux eraser** `strixwipe` — a CLI with hardware sanitize
  (`blkdiscard` / `nvme sanitize` / `hdparm`) and multi-pass overwrite
  (`zero` / `random` / `dod`), built on a **pure, unit-tested safety shield**
  (`strix_disk_cleaner_core.py`, `tests/test_safety.py`).
- Linux packaging: launcher, `install.sh`/`uninstall.sh`, `.deb` builder. **No
  application-menu entry** — a destructive tool is CLI-only by design.
- Loopback-based testing workflow documented (rehearse on `/dev/loopN`, never a real disk).

### Changed
- **Source fully translated to English.** The Windows app already ran with an English UI;
  its 29 function names, all 157 comments, and every internal variable were translated from
  Turkish to English (the AST-based variable rename touches only code tokens, never UI
  strings, and the script still parses cleanly). A small set of internal string identifiers
  (XAML `x:Name`s, hashtable/resource keys) remain and will be renamed alongside a Windows
  build/test.

### Security
- **Linux protection shield now resolves the kernel block-device graph.** Previously the
  Linux `strixwipe` decided "is this disk in use?" by string-normalizing mount sources to a
  whole-disk name — which **missed LVM / LUKS / MD / swap**, so on a common encrypted-Ubuntu
  or server layout it could have erased the physical disk backing the running system. It now
  walks `/sys` holders/partitions (recursively) and `/proc/swaps`, protecting a disk if
  anything stacked on it is mounted, is root, or is active swap. Regression tests added for
  LVM/LUKS/MD/swap (`tests/test_safety.py`).
- **Guaranteed full overwrite.** `_overwrite` now loops on `os.write`'s return value so a
  short write can never leave the tail of the device un-erased while reporting success; the
  sizing file descriptor is no longer leaked.
- **Root launcher no longer trusts user env.** When run as root, `linux/strixwipe` uses a
  fixed interpreter and installed app dir (ignores `$STRIXWIPE_HOME`/`$PATH`), closing a
  root-code-execution path under a permissive sudoers policy.
- **Absolute-path self-elevation on Windows.** The in-script UAC relaunch now uses the
  full `System32\WindowsPowerShell\v1.0\powershell.exe` path instead of a bare
  `powershell.exe`, closing a theoretical `%PATH%`-hijack elevation vector (the installers
  already used the absolute path). See `SECURITY.md`.

### Known follow-ups
- Consider re-running the deep `Assert-DiskProtection` protection check inside the destructive
  raw-write *speed test* path as well (it is already protected by the unselectable
  system disk + `Test-SafetyWall`, but a redundant deep re-check would add defense-in-depth).
