"""
config.py — Global configuration for eBPF-Shield.

Centralises every tunable constant, file path, and syscall identifier so that
the rest of the codebase never hard-codes magic values.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import FrozenSet, List

# =============================================================================
# Project root & data directory
# =============================================================================
PROJECT_ROOT: Path = Path(__file__).resolve().parent
DATA_DIR: Path = PROJECT_ROOT / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

# =============================================================================
# Sliding-window parameters
# =============================================================================
WINDOW_SECONDS: float = 2.0
"""Duration (in seconds) of the per-PID behavioural window."""

# =============================================================================
# Anomaly-detection parameters
# =============================================================================
ANOMALY_THRESHOLD: float = -0.5
"""Isolation Forest score below which a window is considered anomalous."""

CONTAMINATION: float = 0.05
"""Expected fraction of anomalous samples during training."""

# =============================================================================
# Persistence paths
# =============================================================================
MODEL_PATH: Path = DATA_DIR / "model.joblib"
"""Serialised Isolation Forest model."""

SCALER_PATH: Path = DATA_DIR / "scaler.joblib"
"""Serialised StandardScaler fitted during training."""

TRAINING_LOG_PATH: Path = DATA_DIR / "training_log.json"
"""JSON log produced during training (feature stats, metrics, …)."""

FORENSIC_LOG_PATH: Path = DATA_DIR / "forensic_log.jsonl"
"""Append-only JSONL file written when a process is killed."""

# =============================================================================
# Process protection
# =============================================================================
PROTECTED_COMMS: FrozenSet[str] = frozenset({
    "systemd",
    "sshd",
    "init",
    "kthreadd",
    "ebpf-shield",
    "main.py",
    "sudo",
    "su",
    "bash",
    "systemd-user",
    "systemd-userwor",
    "systemd-logind",
})
"""Process comm names that must never be killed."""

# =============================================================================
# Syscall tracepoint hooks
# =============================================================================
SYSCALL_HOOKS: List[str] = [
    "sys_enter_execve",
    "sys_enter_openat",
    "sys_enter_connect",
    "sys_enter_ptrace",
    "sys_enter_setuid",
    "sys_enter_clone",
    "sys_enter_write",
    "sys_enter_mprotect",
    "sys_enter_mmap",
    "sys_enter_execveat",
    "sys_enter_sendto",
    "sys_enter_recvfrom",
    "sys_enter_read",
    "sys_enter_socket",
    "sys_enter_unlink",
    "sys_enter_rename",
]
"""Tracepoint names attached by the eBPF probes."""

# =============================================================================
# Syscall ID constants  (used in the eBPF C program *and* Python feature
# extraction so they must stay perfectly in sync)
# =============================================================================
SYSCALL_EXECVE:   int = 0
SYSCALL_OPENAT:   int = 1
SYSCALL_CONNECT:  int = 2
SYSCALL_PTRACE:   int = 3
SYSCALL_SETUID:   int = 4
SYSCALL_CLONE:    int = 5
SYSCALL_WRITE:    int = 6
SYSCALL_MPROTECT: int = 7
SYSCALL_MMAP:     int = 8
SYSCALL_EXECVEAT: int = 9
SYSCALL_SENDTO:   int = 10
SYSCALL_RECVFROM: int = 11
SYSCALL_READ:     int = 12
SYSCALL_SOCKET:   int = 13
SYSCALL_UNLINK:   int = 14
SYSCALL_RENAME:   int = 15

NUM_SYSCALLS: int = 16
"""Total number of distinct monitored syscall types."""

# =============================================================================
# Ransomware detection parameters
# =============================================================================
RANSOMWARE_WINDOW_SECONDS: float = 10.0
"""Duration for ransomware-specific behavioral window."""

RANSOMWARE_FILE_COUNT_THRESHOLD: int = 50
"""Unique file opens in ransomware window to trigger alert."""

RANSOMWARE_DELETE_THRESHOLD: int = 20
"""Delete operations in ransomware window to trigger alert."""

RANSOMWARE_WRITE_NEW_FILES_THRESHOLD: int = 30
"""New file creations (O_CREAT|O_WRONLY) to trigger alert."""

RANSOM_EXTENSIONS: FrozenSet[str] = frozenset({
    ".encrypted", ".locked", ".crypto", ".ransom",
    ".wncry", ".wannacry", ".petya", ".bad",
})
"""File extensions added by ransomware."""

RANSOM_NOTE_PATTERNS: FrozenSet[str] = frozenset({
    "DECRYPT", "RANSOM", "BITCOIN", "PAYMENT", "README",
    "HOW_TO_DECRYPT", "INSTRUCTIONS", "RESTORE_FILES",
})
"""Strings in ransom note filenames."""

# =============================================================================
# Lateral movement detection parameters
# =============================================================================
LATERAL_MOVEMENT_WINDOW: float = 5.0
"""Duration for lateral movement behavioral window."""

SSH_BINARIES: FrozenSet[str] = frozenset({
    "/usr/bin/ssh", "/usr/bin/scp", "/usr/bin/rsync",
    "/usr/bin/slogin", "/bin/ssh", "/bin/scp", "/bin/slogin",
})
"""Remote execution binary paths."""

SENSITIVE_PROC_PATHS: FrozenSet[str] = frozenset({
    "/proc/self/mem", "/proc/1/mem", "/proc/self/maps",
    "/dev/mem", "/dev/kmem",
})
"""Paths used for credential dumping."""

CREDENTIAL_ACCESS_PATTERNS: FrozenSet[str] = frozenset({
    "/mem", "/kmem", ".ssh/id_rsa", ".ssh/id_ed25519",
    ".ssh/id_ecdsa", ".ssh/id_dsa",
})
"""Path patterns indicating credential access."""

# =============================================================================
# C2 communication detection parameters
# =============================================================================
C2_WINDOW_SECONDS: float = 30.0
"""Duration for C2 beaconing detection window."""

BEACON_VARIANCE_THRESHOLD: float = 0.1
"""Maximum variance in connection intervals for beaconing detection."""

DNS_TUNNEL_QUERY_THRESHOLD: int = 20
"""DNS queries per window to trigger DNS tunneling alert."""

SUSPICIOUS_TLDS: FrozenSet[str] = frozenset({
    "ru", "cn", "tk", "pw", "cc", "top", "xyz", "info", "su", "pw",
})
"""TLDs associated with malicious infrastructure."""

NON_STANDARD_PORTS: FrozenSet[int] = frozenset({
    4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337, 12345, 54321,
})
"""Ports commonly used by malware C2."""

# =============================================================================
# Fileless malware detection parameters
# =============================================================================
FILESS_ELESS_PATTERNS: FrozenSet[str] = frozenset({
    "/dev/shm", "/dev/mqueue", "/run/shm",
    "/tmp/.mem", "/var/run/.mem",
})
"""Paths commonly used for fileless execution."""

MEMFD_PATTERNS: FrozenSet[str] = frozenset({
    "memfd:", "memfd:", "/dev/zero", "/dev/urandom",
})
"""Patterns indicating memfd-based fileless execution."""

# =============================================================================
# Adversarial robustness parameters
# =============================================================================
FEATURE_MIN_VALUES: List[float] = [
    0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,  # First 8 features >= 0
    0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,  # Remaining features >= 0
    0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
    0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
]
"""Minimum allowed values for each feature dimension."""

FEATURE_MAX_VALUES: List[float] = [
    10000.0, 16.0, 1000.0, 1000.0, 1000.0, 1000.0, 1000.0, 1000.0,
    100000.0, 100000.0, 1000.0, 1000.0, 1000.0, 100.0, 100.0, 100.0,
    1000.0, 1000.0, 1000.0, 1000.0, 1000.0, 100.0, 100.0, 100.0,
    100.0, 100.0, 100.0, 100.0, 100.0, 100.0, 100.0, 100.0,
]
"""Maximum allowed values for each feature dimension."""
