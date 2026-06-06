#!/usr/bin/env bash
# =============================================================================
# setup_fedora.sh — Automated Fedora dependency installer for eBPF-Shield
#
# Installs system-level BCC/eBPF tooling, kernel headers, and Python
# dependencies required to run the eBPF-Shield security monitor.
#
# Usage:
#   chmod +x setup_fedora.sh
#   sudo ./setup_fedora.sh
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Colour

info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root (use sudo)."
    exit 1
fi

if ! command -v dnf &>/dev/null; then
    error "dnf not found — this installer targets Fedora."
    exit 1
fi

KERNEL_VERSION=$(uname -r)
info "Detected kernel: ${KERNEL_VERSION}"

# ---------------------------------------------------------------------------
# System packages
# ---------------------------------------------------------------------------
PACKAGES=(
    bcc
    bcc-tools
    python3-bcc
    kernel-devel
    kernel-headers
    python3-pip
    python3-devel
    gcc
    elfutils-libelf-devel
)

info "Updating package cache …"
dnf makecache --refresh -q

info "Installing system packages …"
dnf install -y "${PACKAGES[@]}"

# Verify kernel-devel matches running kernel
if [[ ! -d "/usr/src/kernels/${KERNEL_VERSION}" ]]; then
    warn "kernel-devel for ${KERNEL_VERSION} not found — installing exact match …"
    dnf install -y "kernel-devel-${KERNEL_VERSION}" || \
        warn "Could not install exact kernel-devel. You may need to reboot into the latest kernel."
fi

# ---------------------------------------------------------------------------
# Python dependencies
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REQUIREMENTS="${SCRIPT_DIR}/requirements.txt"

if [[ -f "${REQUIREMENTS}" ]]; then
    info "Installing Python dependencies from requirements.txt …"
    pip3 install --upgrade pip
    pip3 install -r "${REQUIREMENTS}"
else
    warn "requirements.txt not found at ${REQUIREMENTS} — skipping pip install."
fi

# ---------------------------------------------------------------------------
# Create data directory
# ---------------------------------------------------------------------------
DATA_DIR="${SCRIPT_DIR}/data"
mkdir -p "${DATA_DIR}"
info "Data directory ready at ${DATA_DIR}"

# ---------------------------------------------------------------------------
# Sanity check
# ---------------------------------------------------------------------------
info "Running sanity checks …"

if python3 -c "from bcc import BPF" 2>/dev/null; then
    info "✔ python3-bcc import OK"
else
    warn "✘ python3-bcc import failed — check installation."
fi

if python3 -c "import sklearn" 2>/dev/null; then
    info "✔ scikit-learn import OK"
else
    warn "✘ scikit-learn import failed — check pip install."
fi

echo ""
info "========================================="
info " eBPF-Shield dependency setup complete!"
info "========================================="
info "Next steps:"
info "  1. Reboot if a new kernel was installed."
info "  2. Run:  sudo python3 main.py --train"
echo ""
