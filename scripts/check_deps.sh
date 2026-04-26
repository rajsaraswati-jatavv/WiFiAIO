#!/usr/bin/env bash
# WiFiAIO Dependency Checker Script
# Verifies all required and optional dependencies
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
ok() { echo -e "  ${GREEN}✓${NC} $*"; }
miss() { echo -e "  ${RED}✗${NC} $*"; }
opt() { echo -e "  ${YELLOW}○${NC} $* (optional)"; }

check_command() {
    local name="$1"
    local pkg="${2:-$name}"
    if command -v "$name" &>/dev/null; then
        local ver
        ver=$("$name" --version 2>&1 | head -1 || echo "installed")
        ok "$name ($ver)"
        return 0
    else
        miss "$name (install: $pkg)"
        return 1
    fi
}

check_python_module() {
    local module="$1"
    if python3 -c "import $module" 2>/dev/null; then
        local ver
        ver=$(python3 -c "import $module; print($module.__version__)" 2>/dev/null || echo "installed")
        ok "$module ($ver)"
        return 0
    else
        miss "$module (pip install $module)"
        return 1
    fi
}

echo "========================================="
echo "  WiFiAIO Dependency Checker"
echo "========================================="
echo ""

# ── System ──────────────────────────────────────────────────────────────
echo -e "${BLUE}System Information:${NC}"
echo "  OS: $(uname -s) $(uname -r)"
echo "  Arch: $(uname -m)"
echo "  User: $(whoami) $([ $EUID -eq 0 ] && echo '(root)' || echo '(non-root)')"
echo ""

# ── Python ─────────────────────────────────────────────────────────────
echo -e "${BLUE}Python:${NC}"
check_command python3 python3
check_python_module pip
check_python_module venv
echo ""

# ── Core Python Packages ──────────────────────────────────────────────
echo -e "${BLUE}Core Python Packages:${NC}"
check_python_module scapy
check_python_module requests
check_python_module fastapi
check_python_module uvicorn
check_python_module pydantic
check_python_module rich
echo ""

# ── Optional Python Packages ─────────────────────────────────────────
echo -e "${BLUE}Optional Python Packages:${NC}"
check_python_module textual || opt "textual (TUI framework)"
check_python_module numpy || opt "numpy (ML anomaly detection)"
check_python_module cryptography || opt "cryptography (crypto utils)"
check_python_module matplotlib || opt "matplotlib (signal plots)"
echo ""

# ── WiFi Security Tools ──────────────────────────────────────────────
echo -e "${BLUE}WiFi Security Tools:${NC}"
check_command aircrack-ng aircrack-ng
check_command hashcat hashcat
check_command john john
check_command reaver reaver
check_command bully bully || opt "bully"
check_command hcxdumptool hcxdumptool || opt "hcxdumptool"
check_command hcxtools hcxtools || opt "hcxtools"
check_command cowpatty cowpatty || opt "cowpatty"
echo ""

# ── Network Tools ────────────────────────────────────────────────────
echo -e "${BLUE}Network Tools:${NC}"
check_command nmap nmap
check_command tshark wireshark
check_command macchanger macchanger || opt "macchanger"
check_command kismet kismet || opt "kismet"
check_command bettercap bettercap || opt "bettercap"
echo ""

# ── AP/Network Services ──────────────────────────────────────────────
echo -e "${BLUE}AP/Network Services:${NC}"
check_command hostapd hostapd || opt "hostapd (Evil Twin)"
check_command dnsmasq dnsmasq || opt "dnsmasq (DHCP/DNS)"
check_command dhcpd isc-dhcp-server || opt "dhcpd (DHCP server)"
echo ""

# ── Wireless Interface ───────────────────────────────────────────────
echo -e "${BLUE}Wireless Interface:${NC}"
if command -v iw &>/dev/null; then
    interfaces=$(iw dev 2>/dev/null | grep Interface | awk '{print $2}' || true)
    if [[ -n "$interfaces" ]]; then
        for iface in $interfaces; do
            ok "Interface: $iface"
        done
    else
        miss "No wireless interfaces found"
    fi
else
    miss "iw command not found"
fi
echo ""

# ── Capabilities ─────────────────────────────────────────────────────
echo -e "${BLUE}Capabilities:${NC}"
if [[ $EUID -eq 0 ]]; then
    ok "Running as root (full capabilities)"
else
    miss "Not running as root (limited capabilities - use sudo)"
fi

if [[ -f /proc/sys/kernel/yama/ptrace_scope ]]; then
    ptrace=$(cat /proc/sys/kernel/yama/ptrace_scope)
    if [[ "$ptrace" -eq 0 ]]; then
        ok "Ptrace scope allows debugging"
    else
        opt "Ptrace scope restricted (ptrace_scope=$ptrace)"
    fi
fi
echo ""

echo "========================================="
echo "  Dependency check complete"
echo "========================================="
