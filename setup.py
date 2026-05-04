#!/usr/bin/env python3
# ============================================================
# WiFiAIO - Setup Script
# ============================================================

from setuptools import setup, find_packages

setup(
    name="wifiaio",
    version="3.0.0",
    author="T3RMUXK1NG",
    author_email="t3rmuxk1ng@example.com",
    description="All-in-One WiFi Auditing & Security Toolkit",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/t3rmuxk1ng/WiFiAIO",
    license="MIT",
    packages=find_packages(include=["wifi_aio", "wifi_aio.*"]),
    python_requires=">=3.9",
    install_requires=[
        "scapy>=2.5.0",
        "requests>=2.31.0",
        "rich>=13.7.0",
        "textual>=0.47.0",
        "fastapi>=0.109.0",
        "uvicorn[standard]>=0.27.0",
        "websocket-client>=1.7.0",
        "psutil>=5.9.7",
        "netifaces>=0.11.0",
        "python-dotenv>=1.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "pytest-asyncio>=0.23.0",
            "black>=24.1.0",
            "isort>=5.13.0",
            "flake8>=7.0.0",
            "pylint>=3.0.0",
            "mypy>=1.8.0",
            "pre-commit>=3.6.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "wifiaio=wifi_aio.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: System :: Networking :: Wireless",
    ],
    keywords=[
        "wifi", "wireless", "security", "auditing",
        "penetration-testing", "aircrack", "network",
        "scanner", "wpa", "wep",
    ],
    project_urls={
        "Homepage": "https://github.com/t3rmuxk1ng/WiFiAIO",
        "Documentation": "https://github.com/t3rmuxk1ng/WiFiAIO/wiki",
        "Repository": "https://github.com/t3rmuxk1ng/WiFiAIO",
        "Issues": "https://github.com/t3rmuxk1ng/WiFiAIO/issues",
        "Changelog": "https://github.com/t3rmuxk1ng/WiFiAIO/blob/main/CHANGELOG.md",
    },
)
