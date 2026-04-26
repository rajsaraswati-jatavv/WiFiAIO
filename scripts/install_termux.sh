#!/usr/bin/env bash
# WiFiAIO Termux (Android) Installation Script
set -euo pipefail

VERSION="2.0.0"
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info() { echo -e "${BLUE}[INFO]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }
success() { echo -e "${GREEN}[OK]${NC} $*"; }

check_termux() {
    if [[ -z "${TERMUX_VERSION:-}" ]] && ! command -v termux-setup-wifi &>/dev/null; then
        warn "This script is designed for Termux. Some features may not work."
    fi
}

install_termux_deps() {
    info "Installing Termux dependencies..."
    pkg update -y 2>/dev/null || apt-get update -qq
    pkg install -y python python-pip git root-repo 2>/dev/null || {
        apt-get install -y python3 python3-pip git 2>/dev/null || warn "Some packages unavailable"
    }

    # Termux-specific packages
    pkg install -y \
        libpcap openssl toolchain \
        clang make \
        python-numpy python-cryptography \
        2>/dev/null || warn "Some Termux packages unavailable"

    # WiFi tools (require root)
    pkg install -y \
        aircrack-ng hydra nmap \
        2>/dev/null || warn "WiFi security tools require root on Android"
}

install_python_packages() {
    info "Installing Python packages..."
    pip install --upgrade pip setuptools wheel

    # Core packages that work on Termux
    pip install \
        scapy requests pydantic rich \
        2>/dev/null || warn "Some Python packages failed"

    # Optional packages (may fail on Termux)
    pip install \
        fastapi uvicorn textual \
        2>/dev/null || warn "Some optional packages failed"
}

setup_termux_permissions() {
    info "Setting up Termux permissions..."
    # Request WiFi and storage permissions
    termux-setup-wifi 2>/dev/null || true
    termux-setup-storage 2>/dev/null || true

    # Create config directories
    mkdir -p ~/.config/wifi_aio
    mkdir -p ~/.local/share/wifi_aio
    mkdir -p ~/wifi_aio_captures
}

install_wifiaio_termux() {
    info "Installing WiFiAIO for Termux..."
    INSTALL_DIR="${HOME}/wifiaio"
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    PROJECT_DIR="$(dirname "${SCRIPT_DIR}")"

    mkdir -p "${INSTALL_DIR}"
    if [[ -d "${PROJECT_DIR}/wifi_aio" ]]; then
        cp -r "${PROJECT_DIR}"/* "${INSTALL_DIR}/"
    fi

    # Create launcher script
    cat > "${HOME}/bin/wifiaio" << EOF
#!/usr/bin/env bash
cd "${INSTALL_DIR}"
python3 -m wifi_aio "\$@"
EOF
    mkdir -p "${HOME}/bin"
    chmod +x "${HOME}/bin/wifiaio"

    # Add to PATH
    if ! echo "${PATH}" | grep -q "${HOME}/bin"; then
        echo 'export PATH="$HOME/bin:$PATH"' >> ~/.bashrc
    fi

    success "WiFiAIO installed to ${INSTALL_DIR}"
}

show_termux_notes() {
    echo ""
    echo "========================================="
    echo "  WiFiAIO Termux Notes"
    echo "========================================="
    echo ""
    echo "IMPORTANT: WiFiAIO on Termux has limitations:"
    echo "  - Monitor mode requires root (su)"
    echo "  - Not all WiFi tools are available"
    echo "  - Some features are limited on Android"
    echo ""
    echo "Available features without root:"
    echo "  - Network scanning (basic)"
    echo "  - Password analysis"
    echo "  - OSINT lookups"
    echo "  - Compliance checking"
    echo "  - Report generation"
    echo ""
    echo "Features requiring root:"
    echo "  - Packet capture/injection"
    echo "  - Deauthentication"
    echo "  - Evil Twin AP"
    echo "  - WPS attacks"
    echo ""
    echo "Run: wifiaio"
}

main() {
    echo "========================================="
    echo "  WiFiAIO ${VERSION} Termux Installer"
    echo "========================================="
    echo ""

    check_termux
    install_termux_deps
    install_python_packages
    setup_termux_permissions
    install_wifiaio_termux
    show_termux_notes
}

main "$@"
