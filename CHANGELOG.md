# Changelog

All notable changes to WiFiAIO will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-03-04

### Added

- **Core Framework**
  - Modular architecture with plugin-based module system
  - Centralized configuration management with `.env` and YAML support
  - Session management with save, resume, and export capabilities
  - Comprehensive logging with Rich console and file output

- **Scanner Module**
  - Passive and active WiFi network discovery
  - Access point enumeration (SSID, BSSID, channel, encryption, signal)
  - Client/station detection and tracking
  - Hidden network probing
  - Channel hopping with configurable dwell time
  - Real-time scan statistics and filtering

- **Monitor Mode Module**
  - Automatic monitor mode enable/disable
  - Interface management with cleanup on exit
  - Support for multiple wireless interfaces
  - Automatic interface naming (wlan0mon convention)

- **Capture Module**
  - 802.11 frame capture with Scapy integration
  - WPA/WPA2 4-way handshake capture
  - Targeted deauth + handshake capture workflow
  - PCAP/PCAPNG output format support
  - Automatic handshake validation

- **PMKID Module**
  - Client-less PMKID extraction
  - Support for vulnerable AP detection
  - Automatic hash format conversion for hashcat/hashcat

- **Cracking Module**
  - WEP key recovery (ARP replay, fragmentation)
  - WPA/WPA2 dictionary attack
  - Rule-based cracking with hashcat integration
  - Hybrid and mask-based attacks
  - Progress tracking and ETA estimation

- **Deauth Module**
  - Targeted deauthentication attacks
  - Broadcast deauth (all clients)
  - Customizable packet count and interval
  - Multi-target deauth support

- **Evil Twin Module**
  - Rogue access point deployment (hostapd)
  - DHCP server integration (dnsmasq)
  - Captive portal with credential harvesting
  - SSL strip capability
  - Template-based phishing pages

- **WPS Module**
  - WPS PixieDust attack
  - WPS PIN brute-force
  - WPS vulnerability detection
  - Reaver and bully integration

- **Recon Module**
  - WiGLE WiFi geolocation lookup
  - Shodan IoT device discovery
  - SSID and BSSID OSINT enrichment

- **User Interfaces**
  - Full-featured CLI with subcommand architecture
  - Interactive TUI dashboard (Textual)
  - Web dashboard with REST API (FastAPI)
  - Swagger UI and ReDoc API documentation

- **Reporting**
  - JSON, CSV, HTML, and PDF export
  - Session-based audit reports
  - Vulnerability summary and risk scoring

- **Infrastructure**
  - Docker support (Kali Linux based)
  - Docker Compose orchestration
  - Makefile with install, test, lint, docker targets
  - CI/CD pipeline configuration
  - Pre-commit hooks
  - Comprehensive `.gitignore` and `.env.example`
  - MIT License

### Security

- Root/sudo requirement enforcement for sensitive operations
- Input validation and sanitization across all modules
- Secure credential storage in environment variables
- No hardcoded API keys or sensitive data

---

## [0.2.0] - 2025-02-01

### Added

- Scanner module with passive scanning
- Basic handshake capture
- CLI framework with argparse
- Configuration management skeleton

### Changed

- Refactored core engine for modularity
- Improved error handling and logging

### Fixed

- Interface cleanup on interrupted scans
- Channel selection edge cases

---

## [0.1.0] - 2025-01-15

### Added

- Initial project structure
- Basic monitor mode support
- Proof-of-concept packet capture
- Scapy integration

---

[1.0.0]: https://github.com/t3rmuxk1ng/WiFiAIO/releases/tag/v1.0.0
[0.2.0]: https://github.com/t3rmuxk1ng/WiFiAIO/releases/tag/v0.2.0
[0.1.0]: https://github.com/t3rmuxk1ng/WiFiAIO/releases/tag/v0.1.0
