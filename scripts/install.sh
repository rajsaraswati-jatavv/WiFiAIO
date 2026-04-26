#!/usr/bin/env bash
# WiFiAIO Installation Script for Linux
# Supports: Debian/Ubuntu, Fedora/RHEL, Arch, openSUSE
set -euo pipefail

VERSION="2.0.0"
INSTALL_DIR="${INSTALL_DIR:-/opt/wifiaio}"
VENV_DIR="${INSTALL_DIR}/venv"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()  { echo -e "${BLUE}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }
success() { echo -e "${GREEN}[OK]${NC} $*"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root (use sudo)"
    fi
}

detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        echo "${ID}"
    elif command -v lsb_release &>/dev/null; then
        lsb_release -is | tr '[:upper:]' '[:lower:]'
    else
        echo "unknown"
    fi
}

install_deps_debian() {
    info "Installing dependencies for Debian/Ubuntu..."
    apt-get update -qq
    apt-get install -y -qq \
        python3 python3-pip python3-venv \
        aircrack-ng hashcat john reaver \
        hostapd dnsmasq dhcpd \
        wireshark tshark \
        nmap macchanger \
        kismet bettercap \
        rfkill iw wireless-tools \
        libpcap-dev libssl-dev \
        git curl wget \
        2>/dev/null || warn "Some packages may not be available"
}

install_deps_fedora() {
    info "Installing dependencies for Fedora/RHEL..."
    dnf install -y \
        python3 python3-pip python3-devel \
        aircrack-ng hashcat john reaver \
        hostapd dnsmasq dhcp-server \
        wireshark tshark \
        nmap macchanger \
        kismet bettercap \
        rfkill iw wireless-tools \
        libpcap-devel openssl-devel \
        git curl wget \
        2>/dev/null || warn "Some packages may not be available"
}

install_deps_arch() {
    info "Installing dependencies for Arch Linux..."
    pacman -Sy --noconfirm \
        python python-pip python-virtualenv \
        aircrack-ng hashcat john reaver \
        hostapd dnsmasq dhcp \
        wireshark-cli tshark \
        nmap macchanger \
        kismet bettercap \
        rfkill iw wireless_tools \
        libpcap openssl \
        git curl wget \
        2>/dev/null || warn "Some packages may not be available"
}

install_deps_opensuse() {
    info "Installing dependencies for openSUSE..."
    zypper install -y \
        python3 python3-pip python3-devel \
        aircrack-ng hashcat john \
        hostapd dnsmasq dhcp-server \
        wireshark tshark \
        nmap macchanger \
        kismet bettercap \
        rfkill iw wireless-tools \
        libpcap-devel libopenssl-devel \
        git curl wget \
        2>/dev/null || warn "Some packages may not be available"
}

install_python_deps() {
    info "Installing Python dependencies..."
    python3 -m venv "${VENV_DIR}"
    source "${VENV_DIR}/bin/activate"
    pip install --upgrade pip setuptools wheel
    pip install -r "$(dirname "$0")/../requirements.txt" 2>/dev/null || \
    pip install scapy requests fastapi uvicorn pydantic rich textual 2>/dev/null || \
        warn "Some Python packages failed to install"
    deactivate
}

install_wifiaio() {
    info "Installing WiFiAIO ${VERSION}..."
    mkdir -p "${INSTALL_DIR}"

    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    PROJECT_DIR="$(dirname "${SCRIPT_DIR}")"

    if [[ -d "${PROJECT_DIR}/wifi_aio" ]]; then
        cp -r "${PROJECT_DIR}"/* "${INSTALL_DIR}/"
    else
        error "Cannot find wifi_aio source. Run from the project directory."
    fi

    install_python_deps

    cat > /usr/local/bin/wifiaio << 'EOF'
#!/usr/bin/env bash
source /opt/wifiaio/venv/bin/activate
python3 -m wifi_aio "$@"
EOF
    chmod +x /usr/local/bin/wifiaio

    success "WiFiAIO installed to ${INSTALL_DIR}"
}

setup_permissions() {
    info "Setting up permissions..."
    chmod +x "${INSTALL_DIR}/scripts/"*.sh 2>/dev/null || true
    setcap cap_net_raw,cap_net_admin+eip "$(which python3 2>/dev/null || echo /usr/bin/python3)" 2>/dev/null || \
        warn "Could not set capabilities (WiFiAIO may need sudo for some operations)"
}

create_config_dir() {
    mkdir -p /etc/wifiaio
    mkdir -p ~/.config/wifi_aio
    mkdir -p ~/.local/share/wifi_aio
    mkdir -p ~/.cache/wifi_aio
}

main() {
    echo "========================================="
    echo "  WiFiAIO ${VERSION} Installer"
    echo "========================================="
    echo ""

    check_root

    OS_ID=$(detect_os)
    info "Detected OS: ${OS_ID}"

    case "${OS_ID}" in
        ubuntu|debian|linuxmint|pop|elementary)
            install_deps_debian
            ;;
        fedora|rhel|centos|rocky|almalinux)
            install_deps_fedora
            ;;
        arch|manjaro|endeavouros|garuda)
            install_deps_arch
            ;;
        opensuse*|sles)
            install_deps_opensuse
            ;;
        *)
            warn "Unsupported OS: ${OS_ID}. Install dependencies manually."
            ;;
    esac

    install_wifiaio
    setup_permissions
    create_config_dir

    echo ""
    echo "========================================="
    success "WiFiAIO ${VERSION} installed successfully!"
    echo "========================================="
    echo ""
    echo "Run: wifiaio"
    echo "Or:  sudo wifiaio (for operations requiring root)"
    echo ""
    echo "Documentation: https://github.com/wifiaio/wifiaio"
}

main "$@"
