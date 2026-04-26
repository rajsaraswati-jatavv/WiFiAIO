# ============================================================
# WiFiAIO Dockerfile
# Based on Kali Linux with full wireless tool suite
# ============================================================
# Build:  docker build -t wifiaio .
# Run:    docker run --rm -it --net=host --privileged wifiaio
# ============================================================

FROM kalilinux/kali-rolling:latest AS base

LABEL maintainer="RAJSARASWATI JATAV"
LABEL description="WiFiAIO - All-in-One WiFi Auditing & Security Toolkit"
LABEL version="1.0.0"

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PIP_NO_CACHE_DIR=1
ENV PIP_DISABLE_PIP_VERSION_CHECK=1

# -------------------------------------------------------------------
# Stage: System dependencies & wireless tools
# -------------------------------------------------------------------
RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
    # Build essentials
    build-essential \
    gcc \
    g++ \
    make \
    cmake \
    pkg-config \
    libffi-dev \
    libssl-dev \
    libcurl4-openssl-dev \
    libpcap-dev \
    libnet1-dev \
    # Python
    python3 \
    python3-pip \
    python3-dev \
    python3-setuptools \
    python3-wheel \
    # Wireless tools
    aircrack-ng \
    iw \
    wireless-tools \
    rfkill \
    hostapd \
    dnsmasq \
    dnsmasq-utils \
    # Network tools
    nmap \
    net-tools \
    iproute2 \
    iputils-ping \
    traceroute \
    tcpdump \
    wireshark-common \
    tshark \
    ethtool \
    # Security tools
    hashcat \
    john \
    hydra \
    macchanger \
    reaver \
    pixiewps \
    bully \
    cowpatty \
    # Utility
    git \
    curl \
    wget \
    vim \
    sudo \
    netcat-openbsd \
    procps \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# -------------------------------------------------------------------
# Stage: Python dependencies
# -------------------------------------------------------------------
COPY requirements.txt /tmp/requirements.txt

RUN python3 -m pip install --upgrade pip setuptools wheel && \
    python3 -m pip install -r /tmp/requirements.txt && \
    rm -rf /tmp/requirements.txt

# -------------------------------------------------------------------
# Stage: Application setup
# -------------------------------------------------------------------
WORKDIR /opt/wifiaio

# Copy application source
COPY . /opt/wifiaio/

# Install the application in editable mode
RUN python3 -m pip install -e .

# Create necessary directories
RUN mkdir -p /opt/wifiaio/logs \
             /opt/wifiaio/captures \
             /opt/wifiaio/wordlists \
             /opt/wifiaio/data \
             /opt/wifiaio/output

# -------------------------------------------------------------------
# Stage: Final configuration
# -------------------------------------------------------------------
# Expose web dashboard port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "import requests; requests.get('http://localhost:8080/health', timeout=5)" || exit 1

# Entry point
ENTRYPOINT ["python3", "-m", "wifiaio"]

# Default command (can be overridden)
CMD ["--help"]
