"""Unit tests for the Strix Disk Cleaner Linux safety shield (pure functions).

These prove the eraser REFUSES the system/root/mounted/swap disk, including when
the filesystem sits on LVM / LUKS / MD (the case that string-matching missed).
No real device is touched.  Run:  python tests/test_safety.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import strix_disk_cleaner_core as c  # noqa: E402

fails = []


def check(name, cond, extra=""):
    print(("PASS " if cond else "FAIL ") + name + ("  " + extra if extra else ""))
    if not cond:
        fails.append(name)


# --- base_disk ---------------------------------------------------------------
check("base: /dev/sda3 -> /dev/sda", c.base_disk("/dev/sda3") == "/dev/sda")
check("base: /dev/nvme0n1p2 -> /dev/nvme0n1", c.base_disk("/dev/nvme0n1p2") == "/dev/nvme0n1")
check("base: /dev/mmcblk0p1 -> /dev/mmcblk0", c.base_disk("/dev/mmcblk0p1") == "/dev/mmcblk0")
check("base: /dev/md0p1 -> /dev/md0", c.base_disk("/dev/md0p1") == "/dev/md0")
check("base: whole disk unchanged", c.base_disk("/dev/sdb") == "/dev/sdb")

# --- parse_proc_mounts / swaps / root ---------------------------------------
MOUNTS = """/dev/nvme0n1p2 / ext4 rw,relatime 0 0
/dev/nvme0n1p1 /boot/efi vfat rw 0 0
/dev/sda1 /data ext4 rw 0 0
/dev/mapper/vg-root / ext4 rw 0 0
proc /proc proc rw 0 0
"""
m = c.parse_proc_mounts(MOUNTS)
check("mounts: only /dev sources", all(s.startswith("/dev/") for s in m))
check("mounts: mapper source kept", "/dev/mapper/vg-root" in m)

SWAPS = """Filename\tType\tSize\tUsed\tPriority
/dev/sdc2                               partition\t2000000\t0\t-2
/swapfile                               file\t1000000\t0\t-3
"""
sw = c.parse_proc_swaps(SWAPS)
check("swaps: device swap kept, file swap dropped", sw == ["/dev/sdc2"])

check("kernel_name: /dev/sda1 -> sda1", c.kernel_name("/dev/sda1") == "sda1")
check("kernel_name: non-dev -> None", c.kernel_name("proc") is None)

# --- evaluate_protection (PURE) ---------------------------------------------
def ev(disk, descendants, in_use, mounts=None, root=None, swaps=None):
    return c.evaluate_protection(disk, set(descendants), set(in_use),
                                 mounts or {}, root, swaps or [])

# 1) plain system NVMe (root on nvme0n1p2) -> refuse via string fallback
ok, why = ev("/dev/nvme0n1", {"nvme0n1", "nvme0n1p1", "nvme0n1p2"}, set(),
             {"/dev/nvme0n1p2": "/"}, "/dev/nvme0n1p2")
check("REFUSE plain system NVMe", not ok, why)

# 2) /dev/sda with a mounted partition -> refuse (string fallback)
ok, why = ev("/dev/sda", {"sda", "sda1"}, set(), {"/dev/sda1": "/data"})
check("REFUSE disk with a mounted partition", not ok, why)

# 3) LVM: root LV (dm-0) sits on /dev/sdb -> graph catches it
ok, why = ev("/dev/sdb", {"sdb", "dm-0"}, {"dm-0"},
             {"/dev/mapper/vg-root": "/"}, "/dev/mapper/vg-root")
check("REFUSE LVM disk backing root (graph)", not ok, why)

# 4) LUKS+LVM: /dev/sdb -> sdb1 -> dm-0 (crypt) -> dm-1 (LV, mounted)
ok, why = ev("/dev/sdb", {"sdb", "sdb1", "dm-0", "dm-1"}, {"dm-1"},
             {"/dev/mapper/root": "/"}, "/dev/mapper/root")
check("REFUSE LUKS-on-LVM disk (graph)", not ok, why)

# 5) MD RAID member: /dev/sda -> md0 (mounted)
ok, why = ev("/dev/sda", {"sda", "sda1", "md0"}, {"md0"}, {"/dev/md0": "/"}, "/dev/md0")
check("REFUSE MD RAID member disk (graph)", not ok, why)

# 6) active swap on /dev/sdc -> refuse (swap list) even with empty graph/in-use
ok, why = ev("/dev/sdc", {"sdc", "sdc2"}, set(), {}, None, ["/dev/sdc2"])
check("REFUSE disk with active swap", not ok, why)

# 7) clean data disk /dev/sdd, unrelated stuff in use -> ALLOW
ok, why = ev("/dev/sdd", {"sdd"}, {"dm-0", "md0", "nvme0n1p2"},
             {"/dev/nvme0n1p2": "/"}, "/dev/nvme0n1p2", [])
check("ALLOW clean unmounted data disk", ok, why)

# 8) unmounted loopback -> ALLOW (for testing)
ok, why = ev("/dev/loop0", {"loop0"}, set())
check("ALLOW unmounted loop device", ok, why)

# --- disk_hosting_path (PURE) — loop backing-file resolution -----------------
# backing image on the root disk -> resolves to that disk (then refused upstream)
check("host: /var/backup.img -> /dev/sda (root)",
      c.disk_hosting_path("/var/backup.img", {"/dev/sda1": "/"}) == "/dev/sda")
# backing image under a nested data mount -> that disk (longest-prefix wins)
check("host: nested mount picks longest prefix",
      c.disk_hosting_path("/mnt/data/img",
                          {"/dev/sda1": "/", "/dev/sdb1": "/mnt/data"}) == "/dev/sdb")
# backing image on a non-/dev fs (tmpfs/overlay) -> undeterminable -> None
check("host: tmpfs-backed path -> None",
      c.disk_hosting_path("/run/img", {"tmpfs": "/run", "/dev/sda1": "/"}) is None)
# a partition-prefix must NOT false-match (/mnt vs /mnt-data)
check("host: sibling dir does not false-match",
      c.disk_hosting_path("/mnt-data/img",
                          {"/dev/sda1": "/", "/dev/sdb1": "/mnt"}) == "/dev/sda")

print()
if fails:
    print(f"{len(fails)} FAILED: {fails}")
    sys.exit(1)
print("ALL DISK-CLEANER SAFETY TESTS PASSED")
