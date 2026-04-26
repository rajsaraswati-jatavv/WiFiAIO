# WiFiAIO Windows PowerShell Installation Script
# Requires: Windows 10/11, PowerShell 5.1+, Administrator privileges

$ErrorActionPreference = "Stop"
$VERSION = "2.0.0"

function Write-Info($msg) { Write-Host "[INFO] $msg" -ForegroundColor Blue }
function Write-Warn($msg) { Write-Host "[WARN] $msg" -ForegroundColor Yellow }
function Write-Err($msg) { Write-Host "[ERROR] $msg" -ForegroundColor Red }
function Write-Ok($msg) { Write-Host "[OK] $msg" -ForegroundColor Green }

function Test-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Install-Python {
    Write-Info "Checking Python installation..."
    try {
        $pythonVersion = python --version 2>&1
        Write-Ok "Python found: $pythonVersion"
    }
    catch {
        Write-Info "Python not found. Installing Python 3.12..."
        winget install Python.Python.3.12 --accept-source-agreements --accept-package-agreements 2>$null
        if ($LASTEXITCODE -ne 0) {
            Write-Info "Downloading Python installer..."
            $pythonUrl = "https://www.python.org/ftp/python/3.12.0/python-3.12.0-amd64.exe"
            $installer = "$env:TEMP\python-installer.exe"
            Invoke-WebRequest -Uri $pythonUrl -OutFile $installer
            Start-Process -FilePath $installer -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1" -Wait
            Remove-Item $installer -Force
        }
    }
}

function Install-WiFiTools {
    Write-Info "Installing WiFi security tools (Windows)..."

    # Nmap
    try {
        nmap --version 2>$null | Select-Object -First 1
    }
    catch {
        Write-Info "Installing Nmap..."
        winget install Insecure.Nmap --accept-source-agreements --accept-package-agreements 2>$null
    }

    # Wireshark
    try {
        wireshark --version 2>$null | Select-Object -First 1
    }
    catch {
        Write-Info "Installing Wireshark..."
        winget install WiresharkFoundation.Wireshark --accept-source-agreements --accept-package-agreements 2>$null
    }

    # WinPcap/Npcap (required for packet capture)
    if (-not (Test-Path "C:\Windows\System32\Npcap" -ErrorAction SilentlyContinue)) {
        Write-Info "Installing Npcap..."
        $npcapUrl = "https://npcap.com/dist/npcap-1.71.exe"
        $npcapInstaller = "$env:TEMP\npcap-installer.exe"
        try {
            Invoke-WebRequest -Uri $npcapUrl -OutFile $npcapInstaller
            Start-Process -FilePath $npcapInstaller -ArgumentList "/S" -Wait
            Remove-Item $npcapInstaller -Force
        }
        catch {
            Write-Warn "Npcap installation failed. Packet capture features will be limited."
        }
    }
}

function Install-PythonPackages {
    Write-Info "Installing Python packages..."
    python -m pip install --upgrade pip setuptools wheel

    # Core packages
    python -m pip install scapy requests fastapi uvicorn pydantic rich textual

    # Optional packages
    python -m pip install scapy-libs parameterized pytest 2>$null

    Write-Ok "Python packages installed"
}

function Install-WiFiAIO {
    Write-Info "Installing WiFiAIO ${VERSION}..."

    $installDir = "${env:ProgramFiles}\WiFiAIO"
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    $projectDir = Split-Path -Parent $scriptDir

    if (Test-Path "$projectDir\wifi_aio") {
        New-Item -ItemType Directory -Force -Path $installDir | Out-Null
        Copy-Item -Path "$projectDir\*" -Destination $installDir -Recurse -Force
        Write-Ok "WiFiAIO installed to $installDir"
    }
    else {
        Write-Err "Cannot find wifi_aio source directory"
        return
    }

    # Create launcher script
    $launcherContent = @"
@echo off
cd /d "$installDir"
python -m wifi_aio %*
"@
    $launcherPath = "$installDir\wifiaio.bat"
    Set-Content -Path $launcherPath -Value $launcherContent

    # Add to PATH
    $currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    if ($currentPath -notlike "*$installDir*") {
        [Environment]::SetEnvironmentVariable("Path", "$currentPath;$installDir", "Machine")
        Write-Ok "Added WiFiAIO to system PATH"
    }

    # Create Start Menu shortcut
    $shortcutPath = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\WiFiAIO.lnk"
    $ws = New-Object -ComObject WScript.Shell
    $shortcut = $ws.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = "cmd.exe"
    $shortcut.Arguments = "/k `"$launcherPath`""
    $shortcut.WorkingDirectory = $installDir
    $shortcut.Description = "WiFiAIO - All-in-One WiFi Security Toolkit"
    $shortcut.Save()
}

function New-ConfigDirs {
    $dirs = @(
        "$env:APPDATA\wifi_aio",
        "$env:APPDATA\wifi_aio\locales",
        "$env:LOCALAPPDATA\wifi_aio",
        "$env:LOCALAPPDATA\wifi_aio\captures"
    )
    foreach ($dir in $dirs) {
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
    }
    Write-Ok "Configuration directories created"
}

# ── Main ────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "  WiFiAIO $VERSION Windows Installer" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""

if (-not (Test-Admin)) {
    Write-Err "This script must be run as Administrator"
    Write-Host "Right-click PowerShell and select 'Run as Administrator'"
    exit 1
}

Install-Python
Install-WiFiTools
Install-PythonPackages
Install-WiFiAIO
New-ConfigDirs

Write-Host ""
Write-Host "=========================================" -ForegroundColor Green
Write-Ok "WiFiAIO $VERSION installed successfully!"
Write-Host "=========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Run: wifiaio" -ForegroundColor White
Write-Host ""
Write-Host "NOTE: Windows has limited WiFi security features." -ForegroundColor Yellow
Write-Host "For full functionality, use WSL2 or a Linux VM." -ForegroundColor Yellow
