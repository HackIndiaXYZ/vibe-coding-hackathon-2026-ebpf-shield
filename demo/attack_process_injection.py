#!/usr/bin/env python3
"""
attack_process_injection.py — Simulate process injection via ptrace.

⚠️  DEMO / TESTING ONLY — This script forks a dummy child process and
uses the ptrace(PTRACE_ATTACH) system call on it, simulating how
malware injects code into running processes.
"""

import ctypes
import os
import sys
import time

RED = "\033[0;31m"
YELLOW = "\033[1;33m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"

PTRACE_ATTACH = 16

def banner():
    print(f"{RED}╔══════════════════════════════════════════════════════╗{RESET}")
    print(f"{RED}║  ⚠  eBPF-Shield — Process Injection Simulation      ║{RESET}")
    print(f"{RED}╚══════════════════════════════════════════════════════╝{RESET}\n")

def main():
    banner()
    
    print(f"{YELLOW}[STAGE 1]{RESET} {BOLD}Spawning target process{RESET}")
    pid = os.fork()
    
    if pid == 0:
        # Child: Just sleep and act as the target
        time.sleep(10)
        sys.exit(0)
    
    # Parent: The attacker
    time.sleep(0.5)
    print(f"{DIM}  → Target process spawned (PID: {pid}){RESET}\n")
    
    print(f"{YELLOW}[STAGE 2]{RESET} {BOLD}Injecting via ptrace (PTRACE_ATTACH){RESET}")
    print(f"{DIM}  ptrace(PTRACE_ATTACH, {pid}, NULL, NULL){RESET}")
    
    try:
        libc = ctypes.CDLL("libc.so.6")
        res = libc.ptrace(PTRACE_ATTACH, pid, None, None)
        if res == 0:
            print(f"{RED}  ✗ Successfully attached to process {pid}!{RESET}")
        else:
            print(f"{DIM}  → ptrace attach returned {res}{RESET}")
    except Exception as e:
        print(f"{DIM}  → ptrace simulation failed: {e}{RESET}")
        
    print("\n[*] Waiting for eBPF-Shield's in-kernel kill switch...")
    
    # Hold open so the Python killer has time to demonstrate the SIGKILL
    for i in range(10):
        time.sleep(1)
        print(f"{DIM}  ... holding {10-i}s ...{RESET}")
        
    print("\n[-] eBPF-Shield failed to neutralize the threat!")

if __name__ == "__main__":
    main()
