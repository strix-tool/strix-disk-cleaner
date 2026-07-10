#!/usr/bin/env bash
set -euo pipefail
MODE="system"; [ "${1:-}" = "--user" ] && MODE="user"
if [ "$MODE" = "system" ]; then
    [ "$(id -u)" -ne 0 ] && { echo "Need root (or --user)"; exit 1; }
    APPDIR=/opt/strix-disk-cleaner; BINDIR=/usr/local/bin
else
    APPDIR="$HOME/.local/share/strix-disk-cleaner"; BINDIR="$HOME/.local/bin"
fi
rm -rf "$APPDIR"; rm -f "$BINDIR/strixwipe"
echo "Removed strixwipe."
