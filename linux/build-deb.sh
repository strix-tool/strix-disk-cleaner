#!/usr/bin/env bash
# Build a .deb for Strix Disk Cleaner (Linux / strixwipe).
#   ./linux/build-deb.sh [VERSION]
set -euo pipefail
VERSION="${1:-1.0.0}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
PKG="strix-disk-cleaner"; STAGE="$(mktemp -d)"; ROOT="$STAGE/pkg"

mkdir -p "$ROOT/DEBIAN" "$ROOT/opt/$PKG" "$ROOT/usr/bin" "$ROOT/usr/share/doc/$PKG"
install -m 0644 "$REPO/strixwipe.py"               "$ROOT/opt/$PKG/strixwipe.py"
install -m 0644 "$REPO/strix_disk_cleaner_core.py" "$ROOT/opt/$PKG/strix_disk_cleaner_core.py"
install -m 0755 "$REPO/linux/strixwipe"            "$ROOT/usr/bin/strixwipe"
[ -f "$REPO/LICENSE" ] && install -m 0644 "$REPO/LICENSE" "$ROOT/usr/share/doc/$PKG/copyright" || true

cat > "$ROOT/DEBIAN/control" <<EOF
Package: $PKG
Version: $VERSION
Architecture: all
Maintainer: Strix Advanced Tools <noreply@users.noreply.github.com>
Depends: python3, util-linux
Recommends: nvme-cli, hdparm, smartmontools
Section: admin
Priority: optional
Homepage: https://github.com/strix-tools/strix-disk-cleaner
Description: Secure whole-disk eraser (CLI) with a strong safety shield
 Irreversibly erases a whole disk on Linux with hardware sanitize (blkdiscard /
 nvme sanitize / hdparm) or multi-pass overwrite. Refuses the system/root disk
 and any mounted disk, and requires typed confirmation. Command-line only by
 design - never one accidental click away.
EOF

mkdir -p "$REPO/dist"
OUT="$REPO/dist/${PKG}_${VERSION}_all.deb"
dpkg-deb --build --root-owner-group "$ROOT" "$OUT"
echo "Built: $OUT"
rm -rf "$STAGE"
