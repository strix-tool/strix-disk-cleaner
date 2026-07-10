# Using strixwipe (Strix Disk Cleaner on Linux)

> ⚠️ `strixwipe erase` **permanently destroys all data** on the target disk. There is no
> undo. Always confirm the device path with `strixwipe list` / `lsblk` first.

## 1. List disks (safe)

```bash
strixwipe list
```

Shows each whole disk, its size/type, and whether it is **erasable** or **PROTECTED**
(the system/root disk and any mounted disk are protected).

## 2. Rehearse on a loopback device (recommended first run)

No real disk is touched:

```bash
truncate -s 256M /tmp/t.img
sudo losetup -f --show /tmp/t.img      # prints e.g. /dev/loop0
sudo strixwipe erase /dev/loop0 --method zero --yes-really-erase
#   -> type /dev/loop0, then type ERASE
sudo losetup -d /dev/loop0             # detach
rm /tmp/t.img
```

## 3. Erase a real data disk

First **unmount every partition** of the target disk (the tool refuses a disk with any
mounted partition):

```bash
sudo umount /dev/sdX*                   # unmount all partitions
sudo strixwipe erase /dev/sdX --method blkdiscard --yes-really-erase
```

You will be asked to type the device path and `ERASE` to proceed.

## Choosing a method

| Method | Best for | Notes |
|---|---|---|
| `blkdiscard` | SSD / NVMe | Fast TRIM/discard of the whole device. **Preferred on flash.** |
| `nvme-sanitize` | NVMe SSD | Hardware sanitize (needs `nvme-cli`); most thorough for flash. |
| `hdparm-secure` | SATA SSD/HDD | ATA Secure Erase — driven manually with `hdparm` (see notes). |
| `zero` | HDD | Single zero-fill pass. |
| `random` | HDD | Single cryptographic-random pass. |
| `dod` | HDD | 3 passes (zeros, ones, random), DoD 5220.22-M style. |

**On SSDs/NVMe, prefer a hardware method** — overwriting is unreliable on flash because of
wear levelling. `strixwipe` warns you if you pick an overwrite method on a non-rotational
device.

## After erasing

Recreate a partition table if you want to reuse the disk:

```bash
sudo parted /dev/sdX mklabel gpt
```
