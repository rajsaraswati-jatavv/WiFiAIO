#!/usr/bin/env bash
# WiFiAIO Uninstall Script
# Removes WiFiAIO and optionally its data
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info() { echo -e "${BLUE}[INFO]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
ok() { echo -e "${GREEN}[OK]${NC} $*"; }

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[ERROR]${NC} Run with sudo: sudo $0"
    exit 1
fi

echo "========================================="
echo "  WiFiAIO Uninstaller"
echo "========================================="
echo ""
echo "This will remove WiFiAIO from your system."
echo ""
read -rp "Remove user data too? (y/N): " REMOVE_DATA
echo ""

# Remove installation directory
for dir in /opt/wifiaio ~/wifiaio; do
    if [[ -d "$dir" ]]; then
        info "Removing installation: $dir"
        rm -rf "$dir"
        ok "Removed $dir"
    fi
done

# Remove CLI entry points
for bin in /usr/local/bin/wifiaio /usr/local/bin/monstart /usr/local/bin/monstop ~/bin/wifiaio; do
    if [[ -f "$bin" ]]; then
        rm -f "$bin"
        ok "Removed $bin"
    fi
done

# Remove desktop entry
if [[ -f /usr/share/applications/wifiaio.desktop ]]; then
    rm -f /usr/share/applications/wifiaio.desktop
    ok "Removed desktop entry"
fi

# Remove NetworkManager config
if [[ -f /etc/NetworkManager/conf.d/wifiaio.conf ]]; then
    rm -f /etc/NetworkManager/conf.d/wifiaio.conf
    systemctl restart NetworkManager 2>/dev/null || true
    ok "Removed NetworkManager config"
fi

# Remove system config
if [[ -d /etc/wifiaio ]]; then
    rm -rf /etc/wifiaio
    ok "Removed system config"
fi

# Optionally remove user data
if [[ "${REMOVE_DATA}" == "y" || "${REMOVE_DATA}" == "Y" ]]; then
    info "Removing user data..."
    rm -rf ~/.config/wifi_aio
    rm -rf ~/.local/share/wifi_aio
    rm -rf ~/.cache/wifi_aio
    rm -rf ~/wifi_aio_captures
    ok "User data removed"
else
    info "User data preserved in ~/.config/wifi_aio and ~/.local/share/wifi_aio"
fi

echo ""
echo "========================================="
ok "WiFiAIO has been uninstalled"
echo "========================================="
