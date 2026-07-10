#!/usr/bin/env python3
"""strixwipe - Strix Disk Cleaner (Linux): securely erase a whole disk.

  strixwipe list                       list disks (safe to run as user)
  strixwipe info   /dev/sdX            show a disk + whether it's erasable
  strixwipe erase  /dev/sdX [options]  IRREVERSIBLY erase a disk (root only)

Erase methods (--method):
  blkdiscard   TRIM/discard the whole device (fast; good for SSD/NVMe)   [default for SSD]
  nvme-sanitize  ATA/NVMe hardware sanitize (best for SSD; needs nvme-cli)
  hdparm-secure  ATA Secure Erase (SATA SSD/HDD; needs hdparm)
  zero         overwrite with zeros (one pass)                          [default for HDD]
  random       overwrite with cryptographic random (one pass)
  dod          3 passes: zeros, ones, random (DoD 5220.22-M style)

SAFETY: the target disk must be COMPLETELY UNMOUNTED and must not hold '/'. You must
also type the device path and the word ERASE to confirm, and pass --yes-really-erase.
On SSD/NVMe, prefer a hardware method (blkdiscard/sanitize) over overwrite - wear
levelling makes overwrite unreliable on flash.
"""
from __future__ import annotations

import os
import sys
import time
import argparse
import subprocess

import strix_disk_cleaner_core as core

_TTY = sys.stdout.isatty()


def _c(code, s):
    return f"\033[{code}m{s}\033[0m" if _TTY else s


def red(s):    return _c("1;31", s)
def green(s):  return _c("32", s)
def yellow(s): return _c("33", s)
def bold(s):   return _c("1", s)
def dim(s):    return _c("2", s)


def tool(name):
    for d in ("/usr/sbin", "/sbin", "/usr/bin", "/bin"):
        p = os.path.join(d, name)
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None


def disk_kind(d) -> str:
    if d["rotational"]:
        return "HDD"
    return "loop" if d["is_loop"] else "SSD"


# --------------------------------------------------------------------------- #
def cmd_list(args):
    disks = core.list_block_devices()
    print(bold(f"{'DEVICE':<16}{'SIZE':>10}  {'TYPE':<5} {'STATUS':<10} MODEL"))
    for d in disks:
        ok, _ = core.protection_check(d["dev"])
        status = green("erasable") if ok else red("PROTECTED")
        kind = disk_kind(d)
        print(f'{d["dev"]:<16}{core.human_size(d["size_bytes"]):>10}  '
              f'{kind:<5} {status:<19} {d["model"]}')
    return 0


def cmd_info(args):
    d = core.device_summary(args.device)
    if not d:
        print(red(f"{args.device}: not a known block device"))
        return 1
    ok, why = core.protection_check(args.device)
    print(bold(f'Device : {d["dev"]}'))
    print(f'Model  : {d["model"]}')
    print(f'Serial : {d["serial"]}')
    print(f'Size   : {core.human_size(d["size_bytes"])}')
    print(f'Type   : {disk_kind(d)}')
    print(f'Erase  : {green("allowed") if ok else red("REFUSED - " + why)}')
    return 0 if ok else 2


# --------------------------------------------------------------------------- #
def _overwrite(dev, pattern, passes, label):
    """Overwrite the raw device. pattern: b'zero' | b'one' | b'rand'."""
    fd0 = os.open(dev, os.O_RDONLY)
    try:
        size = os.lseek(fd0, 0, os.SEEK_END)
    finally:
        os.close(fd0)
    block = 4 * 1024 * 1024
    for p in range(passes):
        fd = os.open(dev, os.O_WRONLY)
        try:
            written = 0
            os.lseek(fd, 0, os.SEEK_SET)
            while written < size:
                n = min(block, size - written)
                if pattern == b"rand":
                    buf = os.urandom(n)
                elif pattern == b"one":
                    buf = b"\xff" * n
                else:
                    buf = b"\x00" * n
                # Handle short writes: keep writing until the whole buffer lands
                # on the device (a partial os.write must never be counted as a
                # full block, or the tail of the disk would be left un-erased).
                mv = memoryview(buf)
                while mv:
                    w = os.write(fd, mv)
                    if w <= 0:
                        raise IOError("short write near offset %d" % written)
                    mv = mv[w:]
                    written += w
                if _TTY and written % (block * 16) < block:
                    pct = written * 100 // size
                    print(f"\r  {label} pass {p+1}/{passes}: {pct}%  "
                          f"({core.human_size(written)}/{core.human_size(size)})",
                          end="", flush=True)
            os.fsync(fd)
        finally:
            os.close(fd)
        if _TTY:
            print()
    return size


def _run_tool(argv):
    print(dim("  running: " + " ".join(argv)))
    r = subprocess.run(argv)
    return r.returncode == 0


def cmd_erase(args):
    if not core.is_root():
        print(red("erase requires root. Re-run with sudo."))
        return 1

    dev = args.device
    d = core.device_summary(dev)
    if not d:
        print(red(f"{dev}: not a whole-disk block device (partitions are not accepted)"))
        return 1
    # normalise to whole disk and refuse partitions
    if core.base_disk(dev) != dev:
        print(red(f"Refusing a partition. Target the whole disk: {core.base_disk(dev)}"))
        return 1

    ok, why = core.protection_check(dev)
    if not ok:
        print(red(f"PROTECTED: {why}"))
        return 2

    # Big warning
    print(red("=" * 64))
    print(red("  IRREVERSIBLE DESTRUCTION"))
    print(red("=" * 64))
    print(f'  Device : {dev}')
    print(f'  Model  : {d["model"]}  Serial: {d["serial"]}')
    print(f'  Size   : {core.human_size(d["size_bytes"])}')
    print(f'  Method : {args.method}')
    is_ssd = not d["rotational"]
    if is_ssd and args.method in ("zero", "random", "dod"):
        print(yellow("  NOTE: this looks like an SSD/flash device. Overwriting is NOT "
                     "reliable\n        on flash (wear levelling). Prefer --method "
                     "blkdiscard or nvme-sanitize."))
    print(red("=" * 64))

    if not args.yes_really_erase:
        print(yellow("Dry run. Re-run with --yes-really-erase to actually erase."))
        return 0

    # Typed confirmation
    try:
        c1 = input(f'Type the device path to confirm ({dev}): ').strip()
        c2 = input('Type ERASE (uppercase) to proceed: ').strip()
    except (EOFError, KeyboardInterrupt):
        print("\nAborted."); return 130
    if c1 != dev or c2 != "ERASE":
        print(red("Confirmation did not match. Aborted."))
        return 1

    # TOCTOU re-check: the disk (and everything stacked on it) must STILL be
    # safe right before we write.
    ok, why = core.protection_check(dev)
    if not ok:
        print(red(f"PROTECTED (re-check): {why}. Aborted."))
        return 2

    print(bold(f"Erasing {dev} …"))
    t0 = time.time()
    ok = _do_method(dev, args)
    if not ok:
        print(red("Erase method failed. See messages above."))
        return 1
    print(green(f"Done in {time.time()-t0:.0f}s. Consider re-partitioning: "
                f"parted {dev} mklabel gpt"))
    return 0


def _do_method(dev, args) -> bool:
    m = args.method
    if m == "blkdiscard":
        t = tool("blkdiscard")
        if not t:
            print(red("blkdiscard not found (apt install util-linux)"))
            return False
        return _run_tool([t, "-f", dev])
    if m == "nvme-sanitize":
        t = tool("nvme")
        if not t:
            print(red("nvme-cli not found (apt install nvme-cli)")); return False
        return _run_tool([t, "sanitize", dev, "-a", "2"]) or _run_tool([t, "format", dev])
    if m == "hdparm-secure":
        print(yellow("ATA Secure Erase must be driven manually with hdparm; see docs "
                     "(set a user password, then --security-erase). Not automated for safety."))
        return False
    if m == "zero":
        _overwrite(dev, b"zero", 1, "zero"); return True
    if m == "random":
        _overwrite(dev, b"rand", 1, "random"); return True
    if m == "dod":
        _overwrite(dev, b"zero", 1, "zero")
        _overwrite(dev, b"one", 1, "ones")
        _overwrite(dev, b"rand", 1, "random")
        return True
    print(red(f"Unknown method: {m}")); return False


def main(argv=None):
    if not sys.platform.startswith("linux"):
        print("strixwipe is the Linux edition. On Windows use StrixDiskCleaner.ps1.")
        return 1
    p = argparse.ArgumentParser(prog="strixwipe", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="list disks").set_defaults(func=cmd_list)
    s = sub.add_parser("info", help="show a disk"); s.add_argument("device")
    s.set_defaults(func=cmd_info)
    s = sub.add_parser("erase", help="erase a whole disk (root)")
    s.add_argument("device")
    s.add_argument("--method", default="zero",
                   choices=["blkdiscard", "nvme-sanitize", "hdparm-secure",
                            "zero", "random", "dod"])
    s.add_argument("--yes-really-erase", action="store_true",
                   help="required to actually erase (otherwise dry run)")
    s.set_defaults(func=cmd_erase)
    args = p.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\nAborted."); return 130


if __name__ == "__main__":
    sys.exit(main())
