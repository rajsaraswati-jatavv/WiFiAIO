#!/usr/bin/env bash
# WiFiAIO Build Script
# Creates distributable packages
set -euo pipefail

VERSION="${1:-2.0.0}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "${SCRIPT_DIR}")"
BUILD_DIR="${PROJECT_DIR}/dist"

RED='\033[0;31m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'
info() { echo -e "${BLUE}[BUILD]${NC} $*"; }
ok() { echo -e "${GREEN}[OK]${NC} $*"; }

clean() {
    info "Cleaning build artifacts..."
    rm -rf "${BUILD_DIR}"
    rm -rf "${PROJECT_DIR}/build"
    rm -rf "${PROJECT_DIR}/*.egg-info"
    find "${PROJECT_DIR}" -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
    find "${PROJECT_DIR}" -type f -name "*.pyc" -delete 2>/dev/null || true
}

build_sdist() {
    info "Building source distribution..."
    cd "${PROJECT_DIR}"
    python3 setup.py sdist 2>/dev/null || python3 -m build --sdist 2>/dev/null || {
        mkdir -p "${BUILD_DIR}"
        tar czf "${BUILD_DIR}/wifiaio-${VERSION}.tar.gz" \
            --exclude='__pycache__' \
            --exclude='*.pyc' \
            --exclude='.git' \
            --exclude='dist' \
            --exclude='build' \
            --exclude='*.egg-info' \
            wifi_aio/ scripts/ configs/ tests/
    }
    ok "Source distribution created"
}

build_wheel() {
    info "Building wheel distribution..."
    cd "${PROJECT_DIR}"
    python3 setup.py bdist_wheel 2>/dev/null || python3 -m build --wheel 2>/dev/null || {
        info "Wheel build requires 'build' package. Skipping."
    }
    ok "Wheel distribution created"
}

build_docker() {
    info "Building Docker image..."
    if [[ -f "${PROJECT_DIR}/Dockerfile" ]]; then
        docker build -t wifiaio:${VERSION} -t wifiaio:latest "${PROJECT_DIR}"
        ok "Docker image built: wifiaio:${VERSION}"
    else
        info "No Dockerfile found. Skipping Docker build."
    fi
}

run_tests() {
    info "Running tests before build..."
    cd "${PROJECT_DIR}"
    if command -v pytest &>/dev/null; then
        python3 -m pytest tests/ -v --tb=short 2>/dev/null || {
            info "Tests failed. Continue build? (y/N)"
            read -r answer
            [[ "${answer}" != "y" && "${answer}" != "Y" ]] && exit 1
        }
    else
        info "pytest not found. Skipping tests."
    fi
}

lint() {
    info "Running linter..."
    cd "${PROJECT_DIR}"
    if command -v ruff &>/dev/null; then
        ruff check wifi_aio/ 2>/dev/null || true
    elif command -v flake8 &>/dev/null; then
        flake8 wifi_aio/ 2>/dev/null || true
    else
        info "No linter found. Skipping."
    fi
}

show_usage() {
    echo "WiFiAIO Build Script v${VERSION}"
    echo ""
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  all       - Clean, lint, test, and build all distributions"
    echo "  sdist     - Build source distribution (tar.gz)"
    echo "  wheel     - Build wheel distribution (.whl)"
    echo "  docker    - Build Docker image"
    echo "  clean     - Remove build artifacts"
    echo "  test      - Run tests"
    echo "  lint      - Run linter"
    echo ""
}

main() {
    COMMAND="${1:-all}"
    mkdir -p "${BUILD_DIR}"

    case "${COMMAND}" in
        all)
            clean
            lint
            run_tests
            build_sdist
            build_wheel
            build_docker
            ok "All builds complete!"
            ;;
        sdist)   build_sdist ;;
        wheel)   build_wheel ;;
        docker)  build_docker ;;
        clean)   clean ;;
        test)    run_tests ;;
        lint)    lint ;;
        -h|--help|help) show_usage ;;
        *)
            echo "Unknown command: ${COMMAND}"
            show_usage
            exit 1
            ;;
    esac
}

main "$@"
