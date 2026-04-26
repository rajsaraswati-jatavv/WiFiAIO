# Contributing to WiFiAIO

First off, thank you for considering contributing to WiFiAIO! It's people like you that make WiFiAIO such a great tool.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Coding Standards](#coding-standards)
- [Commit Guidelines](#commit-guidelines)
- [Pull Request Process](#pull-request-process)
- [Reporting Bugs](#reporting-bugs)
- [Feature Requests](#feature-requests)
- [Security Vulnerabilities](#security-vulnerabilities)

---

## Code of Conduct

This project and everyone participating in it is governed by our commitment to creating a welcoming, respectful, and inclusive community. By participating, you are expected to:

- Be respectful and constructive
- Focus on what is best for the community
- Show empathy towards other community members
- Refrain from discriminatory, harassing, or offensive behavior

---

## Getting Started

1. **Fork** the repository on GitHub
2. **Clone** your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/WiFiAIO.git
   cd WiFiAIO
   ```
3. **Set up** the development environment:
   ```bash
   make dev-install
   ```
4. **Create** a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```

---

## How to Contribute

### Types of Contributions

| Type | Description |
|---|---|
| **Bug Fixes** | Fix existing issues |
| **New Features** | Add new modules or capabilities |
| **Improvements** | Enhance existing functionality |
| **Documentation** | Improve or add documentation |
| **Tests** | Add or improve test coverage |
| **Refactoring** | Code cleanup without behavior change |

---

## Development Setup

### Prerequisites

- Python 3.9+
- Linux-based OS (Kali recommended)
- WiFi adapter supporting monitor mode (for testing wireless features)
- Docker (optional, for containerized testing)

### Environment Setup

```bash
# Create and activate virtual environment
make dev-install

# Set up environment variables
cp .env.example .env

# Install pre-commit hooks
pre-commit install
```

### Running Tests

```bash
# Run all tests
make test

# Run with coverage
make test-cov

# Run specific test file
pytest tests/test_scanner.py -v

# Run only unit tests (no root required)
pytest tests/ -v -m "not integration"
```

### Code Quality Checks

```bash
# Auto-format code
make format

# Run all linters
make lint

# Type check only
make typecheck

# Full check (lint + test)
make check
```

---

## Coding Standards

### Python Style

- Follow **PEP 8** with line length of **100 characters**
- Use **Black** for code formatting
- Use **isort** for import ordering (profile: black)
- Use **type hints** for all function signatures
- Write **docstrings** for all public functions and classes (Google style)

### Import Order

```python
# Standard library
import os
import sys
from typing import Optional

# Third-party
import requests
from rich.console import Console
from scapy.all import *

# First-party
from wifiaio.core.scanner import Scanner
from wifiaio.utils.helpers import format_bssid
```

### Docstring Format

```python
def scan_networks(interface: str, channel: Optional[int] = None) -> list[dict]:
    """Scan for WiFi networks on the specified interface.

    Args:
        interface: Wireless interface name (e.g., 'wlan0').
        channel: Optional channel to scan. If None, scans all channels.

    Returns:
        List of dictionaries containing network information.

    Raises:
        InterfaceError: If the interface does not exist or is down.
        PermissionError: If insufficient privileges for scanning.
    """
```

### Type Hints

```python
from typing import Optional

def process_packet(packet: "scapy.packet.Packet") -> Optional[dict]:
    ...
```

### Error Handling

- Use specific exception types (not bare `except:`)
- Always include context in error messages
- Use `logging` for warnings and errors, not `print()`
- Let critical errors propagate; catch and handle expected errors

```python
# Good
try:
    iface = get_interface(name)
except InterfaceNotFoundError as e:
    logger.error(f"Interface not found: {name}")
    raise

# Bad
try:
    iface = get_interface(name)
except:
    pass
```

---

## Commit Guidelines

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

### Types

| Type | Description |
|---|---|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation only |
| `style` | Code style (formatting, no behavior change) |
| `refactor` | Code refactoring |
| `perf` | Performance improvement |
| `test` | Adding or updating tests |
| `chore` | Build, CI, or tooling changes |
| `security` | Security-related fix |

### Examples

```
feat(scanner): add hidden network probing support
fix(capture): resolve handshake validation false negatives
docs(README): update installation instructions for Ubuntu
refactor(core): extract interface management to utils
test(cracking): add unit tests for WEP key validation
```

---

## Pull Request Process

1. **Update documentation** if your change affects usage or API
2. **Add tests** for any new functionality
3. **Ensure all checks pass**:
   ```bash
   make check
   ```
4. **Keep PRs focused** — one feature or fix per PR
5. **Write a clear PR description**:
   - What does this change do?
   - Why is it needed?
   - How was it tested?
   - Any breaking changes?

### PR Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
Describe how you tested this change

## Checklist
- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Comments added for complex logic
- [ ] Documentation updated
- [ ] Tests added/updated
- [ ] All CI checks pass
```

### Review Process

- At least one approving review is required
- All CI checks must pass
- Merge conflicts must be resolved
- PR will be squash-merged into `main`

---

## Reporting Bugs

### Before Submitting

1. **Search existing issues** to avoid duplicates
2. **Test with the latest version** to confirm the bug still exists
3. **Gather information**:
   - OS and version
   - Python version
   - WiFi adapter and chipset
   - WiFiAIO version (`wifiaio --version`)
   - Complete command that triggered the bug
   - Full error traceback

### Bug Report Template

```markdown
**Description**
Clear description of the bug

**Environment**
- OS: Kali Linux 2024.1
- Python: 3.11.6
- WiFiAIO: 1.0.0
- WiFi Adapter: Alfa AWUS036NHA (AR9271)

**Steps to Reproduce**
1. Run `sudo wifiaio scan --interface wlan0`
2. Wait for scan to complete
3. Observe error...

**Expected Behavior**
What should happen

**Actual Behavior**
What actually happens

**Logs/Traceback**
```
Paste relevant logs here
```

**Additional Context**
Any other relevant information
```

---

## Feature Requests

We welcome feature requests! Please:

1. **Check existing issues** for similar requests
2. **Describe the use case** — why is this feature needed?
3. **Propose a solution** — how should it work?
4. **Consider alternatives** — are there existing ways to achieve this?

---

## Security Vulnerabilities

**Do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in WiFiAIO:

1. Email the maintainer directly
2. Include a detailed description of the vulnerability
3. Provide steps to reproduce (if applicable)
4. Suggest a fix if you have one

We take security seriously and will respond promptly.

---

## Questions?

Feel free to:
- Open a [GitHub Discussion](https://github.com/rajsaraswati/WiFiAIO/discussions)
- Ask in the issue tracker with the `question` label

Thank you for contributing to WiFiAIO!
