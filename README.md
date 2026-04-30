<p align="center">
  <img src="docs/assets/logo.png" alt="WiFiAIO Logo" width="200"/>
</p>

<h1 align="center">WiFiAIO</h1>

<p align="center">
  <strong>All-in-One WiFi Auditing &amp; Security Toolkit</strong>
</p>

<p align="center">
  <a href="https://github.com/rajsaraswati-jatavv/WiFiAIO/actions">
    <img src="https://img.shields.io/github/actions/workflow/status/rajsaraswati-jatavv/WiFiAIO/ci.yml?branch=main&style=flat-square" alt="CI Status"/>
  </a>
  <a href="https://github.com/rajsaraswati-jatavv/WiFiAIO/releases">
    <img src="https://img.shields.io/github/v/release/rajsaraswati-jatavv/WiFiAIO?style=flat-square" alt="Release"/>
  </a>
  <a href="https://github.com/rajsaraswati-jatavv/WiFiAIO/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/rajsaraswati-jatavv/WiFiAIO?style=flat-square" alt="License"/>
  </a>
  <a href="https://www.python.org/downloads/">
    <img src="https://img.shields.io/badge/python-3.9%2B-blue?style=flat-square" alt="Python Version"/>
  </a>
  <a href="https://github.com/rajsaraswati-jatavv/WiFiAIO/issues">
    <img src="https://img.shields.io/github/issues/rajsaraswati-jatavv/WiFiAIO?style=flat-square" alt="Issues"/>
  </a>
  <a href="https://github.com/rajsaraswati-jatavv/WiFiAIO/stargazers">
    <img src="https://img.shields.io/github/stars/rajsaraswati-jatavv/WiFiAIO?style=flat-square" alt="Stars"/>
  </a>
  <img src="https://img.shields.io/badge/platform-Linux-orange?style=flat-square" alt="Platform"/>
  <img src="https://img.shields.io/badge/code%20style-black-000000?style=flat-square" alt="Code Style"/>
  <a href="https://youtube.com/@T3rmuxk1ng">
    <img src="https://img.shields.io/badge/YouTube-T3rmuxk1ng-red?style=flat-square&logo=youtube" alt="YouTube"/>
  </a>
</p>

---

## Overview

**WiFiAIO** is a comprehensive, modular WiFi security auditing toolkit designed for penetration testers, security researchers, and network administrators. It integrates multiple wireless assessment capabilities into a single, unified platform with both a powerful CLI and an interactive TUI dashboard.

> **Disclaimer**: This tool is intended for authorized security auditing and educational purposes only. Unauthorized access to computer networks is illegal. Always obtain proper authorization before scanning or testing any network.

---

## Features

- **Network Discovery** — Scan and enumerate WiFi access points, clients, and hidden networks
- **Monitor Mode Management** — Enable/disable monitor mode with automatic interface handling
- **Packet Capture & Analysis** — Capture and dissect 802.11 frames with protocol-level detail
- **Handshake Capture** — Deauth and capture WPA/WPA2 4-way handshakes for offline analysis
- **PMKID Attack** — Client-less attack vector for retrieving PMKID from vulnerable APs
- **WEP Cracking** — Automated WEP key recovery via ARP replay and other vectors
- **WPA/WPA2 Cracking** — Dictionary, rule-based, and hybrid cracking with hashcat integration
- **Evil Twin / Rogue AP** — Deploy captive portal and credential harvesting access points
- **Deauthentication Attacks** — Targeted and broadcast deauth with flexible options
- **MAC Spoofing** — Randomize or spoof client/AP MAC addresses
- **Channel Hopping** — Intelligent channel scanning with configurable dwell time
- **Vulnerability Detection** — Identify WEP, WPS, and weak encryption configurations
- **Interactive TUI** — Rich terminal user interface with real-time monitoring dashboards
- **Web Dashboard** — Browser-based control panel with REST API (FastAPI)
- **Session Management** — Save, resume, and organize audit sessions
- **Report Generation** — Export findings as JSON, CSV, HTML, or PDF reports

---

## Architecture

```
WiFiAIO/
├── src/
│   └── wifiaio/
│       ├── cli/              # Command-line interface
│       ├── tui/              # Textual TUI dashboard
│       ├── web/              # FastAPI web dashboard
│       ├── core/             # Core engine & scanner
│       ├── modules/          # Feature modules
│       │   ├── scanner/      # Network discovery
│       │   ├── capture/      # Packet & handshake capture
│       │   ├── cracking/     # WEP/WPA cracking
│       │   ├── deauth/       # Deauthentication
│       │   ├── evil_twin/    # Rogue AP & captive portal
│       │   ├── wps/          # WPS attacks (PixieDust, etc.)
│       │   └── recon/        # OSINT & reconnaissance
│       ├── utils/            # Utility functions
│       └── config/           # Configuration management
├── tests/                    # Test suite
├── docs/                     # Documentation
├── wordlists/                # Default wordlists
├── captures/                 # Captured data (gitignored)
├── logs/                     # Log files (gitignored)
└── data/                     # Database & state (gitignored)
```

---

## Prerequisites

| Requirement | Details |
|---|---|
| **OS** | Linux (Kali, Ubuntu 22.04+, Debian 12+) |
| **Python** | 3.9 or higher |
| **WiFi Adapter** | Chipset supporting monitor mode & packet injection (e.g., Atheros AR9271, Ralink RT3070, Mediatek MT7612U) |
| **Root/Sudo** | Required for monitor mode, packet injection, and channel manipulation |
| **Wireless Tools** | `aircrack-ng`, `iw`, `wireless-tools`, `rfkill` |

### Supported WiFi Adapter Chipsets

- Atheros AR9271 (ath9k_htc)
- Ralink RT3070 (rt2800usb)
- Mediatek MT7612U (mt76u)
- Realtek RTL8812AU (rtl8812au)
- Realtek RTL8821CU (rtl8821cu)

---

## Installation

### Option 1: Quick Install (Recommended)

```bash
# Clone the repository
git clone https://github.com/rajsaraswati-jatavv/WiFiAIO.git
cd WiFiAIO

# Set up environment
cp .env.example .env
make install
```

### Option 2: Development Install

```bash
git clone https://github.com/rajsaraswati-jatavv/WiFiAIO.git
cd WiFiAIO

cp .env.example .env
make dev-install
```

### Option 3: Docker

```bash
git clone https://github.com/rajsaraswati-jatavv/WiFiAIO.git
cd WiFiAIO

# Build and run
make docker-build
make docker-run
```

### Option 4: pip (from PyPI)

```bash
pip install wifiaio
```

### Verifying Installation

```bash
wifiaio --version
wifiaio --help
```

---

## Usage

### Command-Line Interface

```bash
# Scan for nearby access points
sudo wifiaio scan --interface wlan0

# Enable monitor mode
sudo wifiaio monitor --interface wlan0 --start

# Capture WPA handshake
sudo wifiaio capture --target "TargetAP" --interface wlan0mon

# Run PMKID attack
sudo wifiaio pmkid --interface wlan0mon --bssid AA:BB:CC:DD:EE:FF

# Crack captured handshake
wifiaio crack --handshake captures/handshake.cap --wordlist wordlists/rockyou.txt

# Launch Evil Twin
sudo wifiaio evil-twin --ssid "FreeWiFi" --interface wlan0

# Launch interactive TUI dashboard
sudo wifiaio tui

# Start web dashboard
wifiaio web --host 0.0.0.0 --port 8080

# Generate audit report
wifiaio report --session latest --format html --output reports/audit.html
```

### Interactive TUI

Launch the rich terminal interface:

```bash
sudo wifiaio tui
```

The TUI provides:
- Real-time AP and client listing
- Live packet statistics
- Interactive scan controls
- Module selection and configuration
- Session management

### Web Dashboard

Start the FastAPI-based web interface:

```bash
wifiaio web --port 8080
```

Then open `http://localhost:8080` in your browser.

REST API documentation is available at:
- Swagger UI: `http://localhost:8080/docs`
- ReDoc: `http://localhost:8080/redoc`

---

## Modules

| Module | Description | Command |
|---|---|---|
| **Scanner** | Passive/active WiFi network discovery | `wifiaio scan` |
| **Monitor** | Monitor mode management | `wifiaio monitor` |
| **Capture** | Packet capture & handshake retrieval | `wifiaio capture` |
| **PMKID** | Client-less PMKID attack | `wifiaio pmkid` |
| **Crack** | Offline WEP/WPA/WPA2 key recovery | `wifiaio crack` |
| **Deauth** | Deauthentication flood & targeted | `wifiaio deauth` |
| **Evil Twin** | Rogue AP with captive portal | `wifiaio evil-twin` |
| **WPS** | WPS PixieDust & brute-force attacks | `wifiaio wps` |
| **Recon** | OSINT & external intelligence | `wifiaio recon` |
| **Report** | Audit report generation | `wifiaio report` |

---

## Configuration

WiFiAIO uses environment variables and configuration files for flexible setup.

1. Copy the example environment file:
   ```bash
   cp .env.example .env
   ```

2. Edit `.env` with your settings:
   ```ini
   WIFIAIO_LOG_LEVEL=DEBUG
   WIFIAIO_DEFAULT_INTERFACE=wlan0
   WIGLE_API_NAME=your_api_name
   WIGLE_API_TOKEN=your_api_token
   ```

3. Configuration files are loaded in order of priority:
   - Environment variables (highest)
   - `.env` file
   - `config/default.yaml` (lowest)

---

## Development

### Setup

```bash
make dev-install
```

### Running Tests

```bash
make test              # Run all tests
make test-cov          # Run with coverage
```

### Code Quality

```bash
make format            # Auto-format with black & isort
make lint              # Run all linters
make typecheck         # Run mypy
make check             # Lint + test
```

### Pre-commit Hooks

```bash
pre-commit install
pre-commit run --all-files
```

---

## Docker

### Build & Run

```bash
# Build the image
make docker-build

# Run interactively (host network + privileged for WiFi access)
make docker-run

# Or use docker compose
make docker-up
make docker-logs
make docker-down
```

### Docker Volumes

| Host Path | Container Path | Purpose |
|---|---|---|
| `./captures` | `/opt/wifiaio/captures` | Packet captures |
| `./wordlists` | `/opt/wifiaio/wordlists` | Cracking wordlists |
| `./logs` | `/opt/wifiaio/logs` | Application logs |
| `./data` | `/opt/wifiaio/data` | Database & state |
| `./output` | `/opt/wifiaio/output` | Reports & exports |

---

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

Quick start:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and release notes.

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## Legal Disclaimer

WiFiAIO is provided for **authorized security auditing and educational purposes only**. The authors assume no liability and are not responsible for any misuse or damage caused by this program. Always:

- Obtain explicit, written permission before testing any network
- Comply with all applicable local, state, and federal laws
- Use responsible disclosure practices for any vulnerabilities discovered
- Never use this tool on networks you do not own or have authorization to test

Unauthorized access to computer networks is a criminal offense in most jurisdictions.

---

## Acknowledgments

- [Aircrack-ng](https://www.aircrack-ng.org/) — The foundation of wireless security auditing
- [Scapy](https://scapy.net/) — Powerful interactive packet manipulation
- [Hashcat](https://hashcat.net/) — World's fastest password recovery tool
- [Textual](https://textual.textualize.io/) — Framework for building terminal UIs
- [Rich](https://rich.readthedocs.io/) — Rich text and beautiful formatting in the terminal

---

<p align="center">
  Built with purpose by <strong>Rajsaraswati Jatav (T3rmuxk1ng)</strong></p>
<p align="center">
  <a href="https://youtube.com/@T3rmuxk1ng">YouTube: @T3rmuxk1ng</a> |
  <a href="https://github.com/rajsaraswati-jatavv">GitHub</a>
</p>
<p align="center">
  <strong>If you found this project useful, give it a star!</strong>
</p>
