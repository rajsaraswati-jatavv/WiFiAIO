#!/usr/bin/env bash
# WiFiAIO Kali Linux Setup Script
# Installs WiFiAIO with Kali-specific configurations
set -euo pipefail

VERSION="2.0.0"
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info() { echo -e "${BLUE}[INFO]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }
success() { echo -e "${GREEN}[OK]${NC} $*"; }

check_kali() {
    if [[ ! -f /etc/kali-version ]] && ! grep -qi "kali" /etc/os-release 2>/dev/null; then
        warn "This script is designed for Kali Linux. Continuing anyway..."
    fi
}

install_kali_tools() {
    info "Installing Kali Linux WiFi security tools..."
    apt-get update -qq

    # Core WiFi tools (most pre-installed on Kali)
    apt-get install -y -qq \
        aircrack-ng hashcat john reaver bully \
        hostapd dnsmasq isc-dhcp-server \
        wireshark tshark \
        nmap macchanger \
        kismet bettercap \
        cowpatty wifite fern-wifi-cracker \
        reaver pixiewps \
        mdk4 mdk3 \
        hcxdumptool hcxtools \
        pcaputils \
        2>/dev/null || warn "Some Kali packages unavailable"

    # Python dependencies
    apt-get install -y -qq \
        python3 python3-pip python3-venv \
        python3-scapy python3-requests \
        python3-rich python3-textual \
        libpcap-dev libssl-dev \
        2>/dev/null || warn "Some Python packages unavailable"
}

setup_monitor_mode() {
    info "Setting up monitor mode support..."
    # Unblock WiFi if rfkill is blocking
    rfkill unblock all 2>/dev/null || true

    # Create monitor mode helper
    cat > /usr/local/bin/monstart << 'EOF'
#!/usr/bin/env bash
IFACE="${1:-wlan0}"
ip link set "$IFACE" down
iw dev "$IFACE" set type monitor
ip link set "$IFACE" up
echo "Monitor mode enabled on $IFACE"
EOF
    chmod +x /usr/local/bin/monstart

    cat > /usr/local/bin/monstop << 'EOF'
#!/usr/bin/env bash
IFACE="${1:-wlan0}"
ip link set "$IFACE" down
iw dev "$IFACE" set type managed
ip link set "$IFACE" up
echo "Managed mode restored on $IFACE"
EOF
    chmod +x /usr/local/bin/monstop
}

setup_network_manager() {
    info "Configuring NetworkManager to not interfere..."
    if command -v systemctl &>/dev/null; then
        # Prevent NetworkManager from managing monitor interfaces
        mkdir -p /etc/NetworkManager/conf.d
        cat > /etc/NetworkManager/conf.d/wifiaio.conf << 'EOF'
[keyfile]
unmanaged-devices=type:wifi;interface-name:mon*;interface-name:wlan*mon

[device]
wifi.scan-rand-mac-address=no
EOF
        systemctl restart NetworkManager 2>/dev/null || true
    fi
}

install_wifiaio() {
    info "Installing WiFiAIO..."
    INSTALL_DIR="/opt/wifiaio"
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    PROJECT_DIR="$(dirname "${SCRIPT_DIR}")"

    mkdir -p "${INSTALL_DIR}"
    if [[ -d "${PROJECT_DIR}/wifi_aio" ]]; then
        cp -r "${PROJECT_DIR}"/* "${INSTALL_DIR}/"
    fi

    # Setup venv
    python3 -m venv "${INSTALL_DIR}/venv"
    source "${INSTALL_DIR}/venv/bin/activate"
    pip install --upgrade pip setuptools wheel
    pip install -r "${INSTALL_DIR}/requirements.txt" 2>/dev/null || \
        pip install scapy requests fastapi uvicorn pydantic rich textual
    if [[ -f "${INSTALL_DIR}/requirements-full.txt" ]]; then
        pip install -r "${INSTALL_DIR}/requirements-full.txt" 2>/dev/null || true
    fi
    deactivate

    # CLI entry point
    cat > /usr/local/bin/wifiaio << 'EOF'
#!/usr/bin/env bash
source /opt/wifiaio/venv/bin/activate
python3 -m wifi_aio "$@"
EOF
    chmod +x /usr/local/bin/wifiaio

    success "WiFiAIO installed to ${INSTALL_DIR}"
}

setup_kali_menu() {
    info "Adding WiFiAIO to Kali menu..."
    mkdir -p /usr/share/applications
    cat > /usr/share/applications/wifiaio.desktop << EOF
[Desktop Entry]
Name=WiFiAIO
Comment=All-in-One WiFi Security Toolkit
Exec=sudo /usr/local/bin/wifiaio
Icon=utilities-terminal
Terminal=true
Type=Application
Categories=System;Security;Network;
Version=${VERSION}
EOF
}

main() {
    if [[ $EUID -ne 0 ]]; then
        error "Run with sudo: sudo $0"
    fi

    echo "========================================="
    echo "  WiFiAIO Kali Linux Setup"
    echo "========================================="
    check_kali
    install_kali_tools
    setup_monitor_mode
    setup_network_manager
    install_wifiaio
    setup_kali_menu

    echo ""
    success "WiFiAIO Kali setup complete!"
    echo "  Run: wifiaio"
    echo "  Monitor: monstart <interface>"
    echo "  Restore: monstop <interface>"
}

main "$@"
