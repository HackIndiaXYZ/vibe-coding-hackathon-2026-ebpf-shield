#!/bin/bash
# ============================================================================
# attack_privesc.sh — Simulate privilege escalation for eBPF-Shield demo
# ============================================================================
#
# ⚠️  DEMO ONLY — This script simulates malicious privilege escalation
# patterns that eBPF-Shield should detect and block.
#
# Expected detections:
#   • sensitive_file_access  — reading /etc/shadow
#   • uid_change_attempt     — attempting setuid via Python
#   • shell_spawn            — spawning a new shell
#   • priv_esc_sequence      — combined pattern triggers chain alert
#
# Usage:
#   chmod +x attack_privesc.sh
#   sudo ./attack_privesc.sh          # needs root for some operations
#
# ============================================================================

set -uo pipefail  # No -e: we expect some commands to fail

# Colors
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
DIM='\033[2m'
BOLD='\033[1m'
RESET='\033[0m'

echo -e "${RED}╔══════════════════════════════════════════════════════╗${RESET}"
echo -e "${RED}║  ⚠  eBPF-Shield — Privilege Escalation Simulation   ║${RESET}"
echo -e "${RED}║     FOR DEMO / TESTING PURPOSES ONLY                ║${RESET}"
echo -e "${RED}╚══════════════════════════════════════════════════════╝${RESET}"
echo ""
sleep 1

# ── Stage 1: Sensitive file access ────────────────────────────────────────

echo -e "${YELLOW}[STAGE 1] ${BOLD}Sensitive File Access${RESET}"
echo -e "${DIM}  Attempting to read /etc/shadow (triggers sensitive_file_access)...${RESET}"
sleep 0.5

cat /etc/shadow > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo -e "${RED}  ✗ Successfully read /etc/shadow (running as root)${RESET}"
else
    echo -e "${DIM}  → Permission denied (expected without root)${RESET}"
fi

echo -e "${DIM}  Reading /etc/sudoers...${RESET}"
cat /etc/sudoers > /dev/null 2>&1 || true

echo -e "${DIM}  Reading SSH keys...${RESET}"
cat ~/.ssh/id_rsa > /dev/null 2>&1 || true
cat /root/.ssh/authorized_keys > /dev/null 2>&1 || true

echo -e "${YELLOW}  → Stage 1 complete: file access pattern generated${RESET}"
echo ""
sleep 1

# ── Stage 2: UID change attempt ──────────────────────────────────────────

echo -e "${YELLOW}[STAGE 2] ${BOLD}UID Change Attempt${RESET}"
echo -e "${DIM}  Attempting to change UID via Python os.setuid() (triggers uid_change_attempt)...${RESET}"
sleep 0.5

# Attempt setuid via Python (will fail without root, but generates the syscall)
python3 -c "
import os, sys
try:
    print(f'  Current UID: {os.getuid()}')
    print(f'  Attempting setuid(0)...')
    os.setuid(0)
    print(f'  UID changed to: {os.getuid()}')
except PermissionError:
    print('  → setuid(0) denied (expected without root)')
except Exception as e:
    print(f'  → setuid failed: {e}')
" 2>/dev/null || echo -e "${DIM}  → Python setuid attempt completed${RESET}"

echo -e "${DIM}  Attempting su to root...${RESET}"
echo "" | su -c "id" root > /dev/null 2>&1 || true

echo -e "${YELLOW}  → Stage 2 complete: UID change pattern generated${RESET}"
echo ""
sleep 1

# ── Stage 3: Shell spawning ─────────────────────────────────────────────

echo -e "${YELLOW}[STAGE 3] ${BOLD}Shell Spawn${RESET}"
echo -e "${DIM}  Spawning a subshell (triggers shell_spawn)...${RESET}"
sleep 0.5

# Spawn a shell that immediately exits
/bin/sh -c "echo '  → Shell spawned (PID: $$)'; exit 0" 2>/dev/null || true

# Spawn bash
/bin/bash -c "echo '  → Bash spawned'; exit 0" 2>/dev/null || true

# Execve pattern: run a command through a fresh shell
echo -e "${DIM}  Executing commands in spawned shell...${RESET}"
/bin/sh -c "id; whoami; uname -a" > /dev/null 2>&1 || true

echo -e "${YELLOW}  → Stage 3 complete: shell spawn pattern generated${RESET}"
echo ""
sleep 1

# ── Stage 4: Privilege escalation sequence ───────────────────────────────

echo -e "${YELLOW}[STAGE 4] ${BOLD}Combined Priv-Esc Sequence${RESET}"
echo -e "${DIM}  Executing rapid sequence (triggers priv_esc_sequence)...${RESET}"
sleep 0.5

# Rapid sequence: read shadow → setuid → spawn shell → read more
cat /etc/shadow > /dev/null 2>&1 || true
python3 -c "import os; os.setuid(0)" 2>/dev/null || true
/bin/sh -c "cat /etc/passwd" > /dev/null 2>&1 || true
cat /etc/sudoers > /dev/null 2>&1 || true
/bin/bash -c "echo escalated; echo 'Holding shell open for eBPF kill...'; sleep 5" > /dev/null 2>&1 || true

echo -e "${DIM}  Checking for SUID binaries...${RESET}"
find /usr/bin -perm -4000 -type f 2>/dev/null | head -5 > /dev/null || true
find /usr/sbin -perm -4000 -type f 2>/dev/null | head -5 > /dev/null || true

echo -e "${DIM}  Attempting to write to /etc/passwd...${RESET}"
echo "hacker:x:0:0::/root:/bin/bash" >> /etc/passwd 2>/dev/null || true

echo -e "${YELLOW}  → Stage 4 complete: priv-esc sequence generated${RESET}"
echo ""
sleep 1

# ── Summary ──────────────────────────────────────────────────────────────

echo -e "${RED}╔══════════════════════════════════════════════════════╗${RESET}"
echo -e "${RED}║  Attack simulation complete!                        ║${RESET}"
echo -e "${RED}║                                                     ║${RESET}"
echo -e "${RED}║  Expected eBPF-Shield detections:                   ║${RESET}"
echo -e "${RED}║    • sensitive_file_access   (Stage 1)              ║${RESET}"
echo -e "${RED}║    • uid_change_attempt      (Stage 2)              ║${RESET}"
echo -e "${RED}║    • shell_spawn             (Stage 3)              ║${RESET}"
echo -e "${RED}║    • priv_esc_sequence        (Stage 4)              ║${RESET}"
echo -e "${RED}╚══════════════════════════════════════════════════════╝${RESET}"
