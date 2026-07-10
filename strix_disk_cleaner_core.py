"""Strix Disk Cleaner - Linux core (safety shield + device enumeration).

The dangerous decision ("is it safe to erase this disk?") is isolated here. The
protection shield resolves the real kernel BLOCK-DEVICE GRAPH via /sys, so it
correctly protects a physical disk that backs the running system through ANY
layer of indirection -- partitions, LVM, LUKS/dm-crypt, MD RAID -- as well as
active swap. It does NOT rely on device-name string matching alone.

A disk is PROTECTED (refused) if any device built on top of it (recursively:
partitions + dm/md holders) is mounted, is the root filesystem, or is active
swap. To wipe a data disk you must unmount/close/swapoff everything on it first.

The pure decision function `evaluate_protection()` takes plain data so it can be
unit-tested exhaustively (see tests/test_safety.py). No overwrite logic lives
here; this module never opens a device for writing.
"""
from __future__ import annotations

import os
import re


# --------------------------------------------------------------------------- #
# Pure helpers (unit-tested)
# --------------------------------------------------------------------------- #
def base_disk(dev: str) -> str:
    """Normalise a partition path to its whole-disk path (pure).

    /dev/sda3      -> /dev/sda      /dev/nvme0n1p2 -> /dev/nvme0n1
    /dev/mmcblk0p1 -> /dev/mmcblk0  /dev/loop0p1   -> /dev/loop0
    /dev/md0p1     -> /dev/md0      (already-whole paths pass through)
    """
    name = dev.rsplit("/", 1)[-1]
    m = re.match(r"^(nvme\d+n\d+|mmcblk\d+|loop\d+|md\d+)p\d+$", name)
    if m:
        return "/dev/" + m.group(1)
    m = re.match(r"^(sd[a-z]+|vd[a-z]+|hd[a-z]+|xvd[a-z]+)\d+$", name)
    if m:
        return "/dev/" + m.group(1)
    return "/dev/" + name


def kernel_name(devpath: str) -> str | None:
    """Resolve a device path to its kernel block-device name (pure-ish; only
    touches the filesystem to follow a symlink). /dev/mapper/vg-root -> 'dm-3',
    /dev/sda1 -> 'sda1'. Returns None for non-/dev paths."""
    if not devpath or not devpath.startswith("/dev/"):
        return None
    try:
        real = os.path.realpath(devpath)
    except OSError:
        real = devpath
    # If realpath didn't resolve into /dev (e.g. a dead symlink, or running the
    # unit tests off-Linux), fall back to the original /dev path's basename.
    if not real.startswith("/dev/"):
        real = devpath
    return real.rsplit("/", 1)[-1]


def parse_proc_mounts(text: str) -> dict:
    """Parse /proc/mounts text -> {source_device: mountpoint} (pure).
    Only real block-device sources (/dev/...) are returned."""
    out = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].startswith("/dev/"):
            src = _unescape(parts[0])
            out[src] = _unescape(parts[1])
    return out


def parse_proc_swaps(text: str) -> list:
    """Parse /proc/swaps -> list of swap device paths (pure).
    Skips the header line and file-backed swap (non-/dev)."""
    out = []
    for line in text.splitlines()[1:]:            # skip header
        parts = line.split()
        if parts and parts[0].startswith("/dev/"):
            out.append(_unescape(parts[0]))
    return out


def _unescape(s: str) -> str:
    # /proc encodes space/tab/backslash/newline as octal \NNN. Decode only those.
    return re.sub(r"\\(\d{3})", lambda m: chr(int(m.group(1), 8)), s)


def root_source(mounts: dict) -> str | None:
    """Return the device backing '/' (pure)."""
    for src, mnt in mounts.items():
        if mnt == "/":
            return src
    return None


def evaluate_protection(disk: str, descendants: set, in_use: set,
                        mounts: dict, root_src: str | None,
                        swaps: list) -> tuple:
    """PURE protection decision. Returns (ok, reason); ok=False means REFUSE.

    * disk          - whole-disk path being targeted, e.g. '/dev/sdb'
    * descendants   - kernel names of every block device built on `disk`
                      (its partitions + dm/md holders, recursive), incl. itself
    * in_use        - kernel names currently mounted / root / active swap
    * mounts        - {source: mountpoint} (string fallback for direct partitions)
    * root_src      - device backing '/'
    * swaps         - list of active swap device paths
    """
    # 1) Primary check: the kernel dependency graph. Catches LVM/LUKS/MD/swap
    #    where the in-use device name never textually contains the disk.
    overlap = descendants & in_use
    if overlap:
        return False, ("in use by %s (mounted / root / swap sits on this disk) "
                       "- close/unmount/swapoff it first" % ", ".join(sorted(overlap)))
    # 2) String fallback: direct partitions on a plainly-partitioned disk, in
    #    case /sys was unreadable and the graph came back empty.
    for src, mnt in mounts.items():
        if base_disk(src) == disk:
            return False, "%s is mounted at %s - unmount the whole disk first" % (src, mnt)
    if root_src and base_disk(root_src) == disk:
        return False, "this disk holds the root (/) filesystem"
    for sw in swaps:
        if base_disk(sw) == disk:
            return False, "%s is active swap on this disk - swapoff it first" % sw
    return True, ""


def disk_hosting_path(real_path: str, mounts: dict) -> str | None:
    """PURE. Return the whole-disk device that hosts `real_path`, found via the
    longest mountpoint that is a path-prefix of it, or None if that mount isn't a
    /dev-backed device. `real_path` must already be resolved (no symlinks)."""
    best_src, best_len = None, -1
    for src, mnt in mounts.items():
        if not mnt:
            continue
        prefix = mnt if mnt == "/" else mnt.rstrip("/") + "/"
        if real_path == mnt or real_path.startswith(prefix):
            if len(mnt) > best_len:
                best_src, best_len = src, len(mnt)
    if best_src and best_src.startswith("/dev/"):
        return base_disk(best_src)
    return None


# --------------------------------------------------------------------------- #
# Live block-device graph (reads /sys and /proc; thin wrappers, not unit-tested)
# --------------------------------------------------------------------------- #
def _read(path: str) -> str | None:
    try:
        with open(path, "r") as f:
            return f.read().strip()
    except OSError:
        return None


def _sys_children(name: str) -> list:
    """Immediate block-device children of `name`: its partitions and its
    dm/md 'holders'. Reads /sys."""
    kids = []
    base = "/sys/block/" + name
    try:                                          # partitions (whole disks only)
        for e in os.listdir(base):
            if os.path.isfile(os.path.join(base, e, "partition")):
                kids.append(e)
    except OSError:
        pass
    try:                                          # dm/md stacked on this device
        kids += os.listdir("/sys/class/block/%s/holders" % name)
    except OSError:
        pass
    return kids


def block_descendants(disk_name: str) -> set:
    """Every block-device kernel name built on `disk_name` (partitions + dm/md
    holders, recursive), including itself. Reads /sys."""
    seen, stack = set(), [disk_name]
    while stack:
        n = stack.pop()
        if n in seen:
            continue
        seen.add(n)
        for child in _sys_children(n):
            if child not in seen:
                stack.append(child)
    return seen


def read_mounts() -> dict:
    return parse_proc_mounts(_read("/proc/mounts") or "")


def read_swaps() -> list:
    return parse_proc_swaps(_read("/proc/swaps") or "")


def in_use_kernel_names() -> set:
    """Kernel device names that are currently mounted, backing root, or active swap."""
    names = set()
    for src in list(read_mounts().keys()) + read_swaps():
        kn = kernel_name(src)
        if kn:
            names.add(kn)
    return names


def protection_check(dev: str) -> tuple:
    """Live safety decision for `dev`. Gathers the /sys graph + /proc state and
    calls the pure evaluator. Returns (ok, reason)."""
    disk = base_disk(dev)
    disk_kn = disk.rsplit("/", 1)[-1]
    mounts = read_mounts()
    swaps = read_swaps()
    # Loop backing-file guard: a detached-but-open loop (e.g. `losetup /dev/loop0
    # /var/backup.img`) whose image lives on a protected disk would let a write to
    # the loop reach that disk through indirection the mount/holder graph misses.
    # Refuse if the backing file resolves onto a protected disk.
    if disk_kn.startswith("loop"):
        backing = _read("/sys/block/%s/loop/backing_file" % disk_kn)
        if backing:
            host = disk_hosting_path(os.path.realpath(backing), mounts)
            if host:
                ok, why = evaluate_protection(
                    host, block_descendants(host.rsplit("/", 1)[-1]),
                    in_use_kernel_names(), mounts, root_source(mounts), swaps)
                if not ok:
                    return False, ("loop backing file %s lives on %s which is "
                                   "protected (%s)" % (backing, host, why))
    return evaluate_protection(disk, block_descendants(disk_kn),
                               in_use_kernel_names(), mounts,
                               root_source(mounts), swaps)


# --------------------------------------------------------------------------- #
# Live enumeration
# --------------------------------------------------------------------------- #
def list_block_devices() -> list:
    """Enumerate whole disks from /sys/block (excludes partitions and virtual
    aggregate/ram devices)."""
    out = []
    try:
        names = sorted(os.listdir("/sys/block"))
    except OSError:
        return out
    for name in names:
        # Drop virtual / aggregate devices; keep real disks (sd/vd/nvme/mmcblk)
        # and loopN (used for safe testing).
        if name.startswith(("ram", "dm-", "sr", "zram", "md")):
            continue
        base = "/sys/block/%s" % name
        sectors = _read("%s/size" % base)
        size = int(sectors) * 512 if sectors and sectors.isdigit() else None
        out.append({
            "dev": "/dev/%s" % name,
            "name": name,
            "size_bytes": size,
            "model": _read("%s/device/model" % base) or "",
            "serial": _read("%s/device/serial" % base) or "",
            "rotational": _read("%s/queue/rotational" % base) == "1",
            "removable": _read("%s/removable" % base) == "1",
            "is_loop": name.startswith("loop"),
        })
    return out


def device_summary(dev: str) -> dict | None:
    for d in list_block_devices():
        if d["dev"] == dev or d["dev"] == base_disk(dev):
            return d
    return None


def human_size(n) -> str:
    if not n:
        return "?"
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024:
            return "%.1f %s" % (n, unit)
        n /= 1024
    return "%.1f PiB" % n


def is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False
