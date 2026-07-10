#!/usr/bin/env bash
# Strix Disk Cleaner (Linux / strixwipe) installer.
# Deliberately a command-line tool with NO application-menu entry - a destructive
# disk eraser should never be one accidental click away.
#   sudo ./install.sh          # system-wide
#        ./install.sh --user   # per-user
set -euo pipefail
MODE="system"; [ "${1:-}" = "--user" ] && MODE="user"
REPO="$(cd "$(dirname "$0")/.." && pwd)"

if [ "$MODE" = "system" ]; then
    [ "$(id -u)" -ne 0 ] && { echo "System install needs root (or --user)"; exit 1; }
    APPDIR=/opt/strix-disk-cleaner; BINDIR=/usr/local/bin
else
    APPDIR="$HOME/.local/share/strix-disk-cleaner"; BINDIR="$HOME/.local/bin"
fi

command -v python3 >/dev/null 2>&1 || { echo "python3 is required"; exit 1; }
if command -v apt-get >/dev/null 2>&1 && [ "$MODE" = "system" ]; then
    apt-get install -y util-linux nvme-cli hdparm smartmontools 2>/dev/null || true
fi

mkdir -p "$APPDIR" "$BINDIR"
install -m 0644 "$REPO/strixwipe.py"                "$APPDIR/strixwipe.py"
install -m 0644 "$REPO/strix_disk_cleaner_core.py"  "$APPDIR/strix_disk_cleaner_core.py"
install -m 0755 "$REPO/linux/strixwipe"             "$BINDIR/strixwipe"

echo "Installed. Usage:"
echo "  strixwipe list                       # safe, lists disks"
echo "  sudo strixwipe erase /dev/sdX --method blkdiscard --yes-really-erase"
echo
echo "IMPORTANT: the target disk must be fully UNMOUNTED. Test on a loopback first:"
echo "  truncate -s 256M /tmp/t.img && sudo losetup -f --show /tmp/t.img"
[ "$MODE" = "user" ] && echo "(Ensure $BINDIR is on your PATH.)"
