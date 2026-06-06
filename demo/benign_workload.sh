#!/bin/bash
# ============================================================================
# benign_workload.sh — Generate normal Linux activity for eBPF-Shield training
# ============================================================================
#
# This script simulates typical benign system activity:
#   - File listing & reading
#   - Network requests (curl/wget)
#   - Temp file operations
#   - Standard system commands
#
# Usage:
#   chmod +x benign_workload.sh
#   ./benign_workload.sh              # default 5 minutes
#   ./benign_workload.sh --duration 60  # 60 seconds
#
# ============================================================================

set -euo pipefail

# ── Configuration ──────────────────────────────────────────────────────────
DURATION=${1:-300}  # Default: 300 seconds (5 minutes)

# Parse named args
while [[ $# -gt 0 ]]; do
    case "$1" in
        --duration|-d)
            DURATION="$2"
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done

START_TIME=$(date +%s)
END_TIME=$((START_TIME + DURATION))
ITERATION=0

# Colors for output
GREEN='\033[0;32m'
CYAN='\033[0;36m'
DIM='\033[2m'
RESET='\033[0m'

echo -e "${CYAN}╔══════════════════════════════════════════════════════╗${RESET}"
echo -e "${CYAN}║  eBPF-Shield — Benign Workload Generator            ║${RESET}"
echo -e "${CYAN}║  Duration: ${DURATION}s                                      ║${RESET}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════╝${RESET}"
echo ""

# ── Benign activity functions ──────────────────────────────────────────────

do_file_listing() {
    echo -e "${DIM}  [file-ops] Listing directories...${RESET}"
    ls /tmp > /dev/null 2>&1 || true
    ls /var/log > /dev/null 2>&1 || true
    ls /usr/bin > /dev/null 2>&1 || true
    ls /home > /dev/null 2>&1 || true
    ls -la /etc > /dev/null 2>&1 || true
    find /tmp -maxdepth 1 -type f > /dev/null 2>&1 || true
}

do_file_reading() {
    echo -e "${DIM}  [file-ops] Reading system files...${RESET}"
    cat /etc/hostname > /dev/null 2>&1 || true
    cat /etc/os-release > /dev/null 2>&1 || true
    cat /etc/resolv.conf > /dev/null 2>&1 || true
    cat /etc/hosts > /dev/null 2>&1 || true
    head -5 /etc/passwd > /dev/null 2>&1 || true
    wc -l /etc/fstab > /dev/null 2>&1 || true
}

do_network() {
    echo -e "${DIM}  [network]  Making HTTP requests...${RESET}"
    if command -v curl &> /dev/null; then
        curl -s -o /dev/null -m 5 https://httpbin.org/get 2>/dev/null || true
        curl -s -o /dev/null -m 5 https://example.com 2>/dev/null || true
        curl -s -o /dev/null -m 5 https://ifconfig.me 2>/dev/null || true
    elif command -v wget &> /dev/null; then
        wget -q -O /dev/null --timeout=5 https://httpbin.org/get 2>/dev/null || true
        wget -q -O /dev/null --timeout=5 https://example.com 2>/dev/null || true
    else
        echo -e "${DIM}  [network]  Neither curl nor wget available, skipping...${RESET}"
    fi
}

do_temp_files() {
    echo -e "${DIM}  [file-ops] Creating/deleting temp files...${RESET}"
    local tmpfile
    for i in $(seq 1 5); do
        tmpfile=$(mktemp /tmp/ebpf_benign_XXXXXX)
        echo "benign data iteration $ITERATION file $i" > "$tmpfile"
        cat "$tmpfile" > /dev/null
        rm -f "$tmpfile"
    done
}

do_system_commands() {
    echo -e "${DIM}  [system]   Running standard commands...${RESET}"
    date > /dev/null 2>&1
    whoami > /dev/null 2>&1
    uname -a > /dev/null 2>&1
    uptime > /dev/null 2>&1 || true
    ps aux > /dev/null 2>&1
    df -h > /dev/null 2>&1
    free -m > /dev/null 2>&1 || true
    id > /dev/null 2>&1
    env > /dev/null 2>&1
    hostname > /dev/null 2>&1 || true
}

do_process_ops() {
    echo -e "${DIM}  [process]  Spawning subprocesses...${RESET}"
    echo "hello" | grep "hello" > /dev/null 2>&1
    echo "test data" | wc -c > /dev/null 2>&1
    seq 1 100 | sort -n > /dev/null 2>&1
    echo "line1\nline2\nline3" | head -2 > /dev/null 2>&1
}

# ── Main loop ──────────────────────────────────────────────────────────────

while [ "$(date +%s)" -lt "$END_TIME" ]; do
    ITERATION=$((ITERATION + 1))
    ELAPSED=$(( $(date +%s) - START_TIME ))
    REMAINING=$(( DURATION - ELAPSED ))

    echo -e "${GREEN}━━━ Iteration ${ITERATION}  |  Elapsed: ${ELAPSED}s  |  Remaining: ${REMAINING}s ━━━${RESET}"

    do_file_listing
    do_file_reading
    do_network
    do_temp_files
    do_system_commands
    do_process_ops

    echo -e "${GREEN}  ✓ Iteration ${ITERATION} complete${RESET}"
    echo ""

    # Sleep 2-5 seconds between iterations (randomized for realism)
    sleep $(( (RANDOM % 4) + 2 ))
done

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════╗${RESET}"
echo -e "${CYAN}║  ✅ Benign workload complete!                       ║${RESET}"
echo -e "${CYAN}║  Total iterations: ${ITERATION}                              ║${RESET}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════╝${RESET}"
