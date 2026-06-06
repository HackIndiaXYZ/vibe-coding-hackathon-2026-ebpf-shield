#!/usr/bin/env python3
"""
attack_fileless_memfd.py — Simulate fileless malware execution.

⚠️  DEMO / TESTING ONLY — This script uses the memfd_create syscall
to allocate an anonymous RAM-backed file, writes a payload into it,
and attempts to execute it directly from memory without touching the disk.
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

# memfd_create syscall number on x86_64
SYS_memfd_create = 319
MFD_CLOEXEC = 1

def banner():
    print(f"{RED}╔══════════════════════════════════════════════════════╗{RESET}")
    print(f"{RED}║  ⚠  eBPF-Shield — Fileless Malware Simulation       ║{RESET}")
    print(f"{RED}╚══════════════════════════════════════════════════════╝{RESET}\n")

def main():
    banner()
    
    print(f"{YELLOW}[STAGE 1]{RESET} {BOLD}Allocating invisible memory file (memfd_create){RESET}")
    
    try:
        libc = ctypes.CDLL("libc.so.6")
        # Creating an anonymous file in RAM (no CLOEXEC so it survives exec)
        fd = libc.syscall(SYS_memfd_create, b"hidden_payload", 0)
        if fd < 0:
            print(f"{DIM}  → memfd_create failed (kernel might not support it){RESET}")
            return
            
        print(f"{RED}  ✗ Memory-backed file created at /proc/self/fd/{fd}{RESET}\n")
    except Exception as e:
        print(f"{DIM}  → setup failed: {e}{RESET}")
        return

    print(f"{YELLOW}[STAGE 2]{RESET} {BOLD}Writing payload to memory{RESET}")
    # A simple bash script payload. Because it starts with #!, execve will invoke /bin/sh.
    payload = b"#!/bin/sh\necho '  [!] Fileless Payload Executed!'\nsleep 10\n"
    os.write(fd, payload)
    
    # We must make the memfd executable
    try:
        os.chmod(f"/proc/self/fd/{fd}", 0o755)
    except Exception as e:
        print(f"{DIM}  → chmod failed: {e}{RESET}")
        
    print(f"{DIM}  → Payload injected into memory{RESET}\n")
    
    print(f"{YELLOW}[STAGE 3]{RESET} {BOLD}Executing payload from memory (execve){RESET}")
    print(f"{DIM}  execve(\"/proc/self/fd/{fd}\"){RESET}")
    time.sleep(0.5)
    
    try:
        # We attempt to execute it. This emits the sys_enter_execve tracepoint!
        os.execv(f"/proc/self/fd/{fd}", ["hidden_payload"])
    except OSError as e:
        print(f"{DIM}  → execve failed (expected if fchmod is required): {e}{RESET}")
        print(f"{DIM}  → Note: The syscall was still generated and eBPF-Shield should catch it!{RESET}")

    print("\n[*] Waiting for eBPF-Shield's in-kernel kill switch...")
    for i in range(10):
        time.sleep(1)
        print(f"{DIM}  ... holding {10-i}s ...{RESET}")
        
    print("\n[-] eBPF-Shield failed to neutralize the threat!")

if __name__ == "__main__":
    main()
