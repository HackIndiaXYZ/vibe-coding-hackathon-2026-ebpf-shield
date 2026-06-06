"""
ebpf/syscall_map.py — Syscall name/ID mapping and sensitive-path definitions.

Provides bidirectional lookup between human-readable syscall names and the
compact integer IDs used inside the eBPF ring-buffer events.  Also enumerates
file paths that are considered security-sensitive for heuristic scoring.
"""

from __future__ import annotations

from typing import Dict, FrozenSet, List, Optional

# =============================================================================
# Syscall ↔ ID mappings
# =============================================================================

SYSCALL_NAME_TO_ID: Dict[str, int] = {
    "execve":   0,
    "openat":   1,
    "connect":  2,
    "ptrace":   3,
    "setuid":   4,
    "clone":    5,
    "write":    6,
    "mprotect": 7,
    "mmap":     8,
    "execveat": 9,
    "sendto":   10,
    "recvfrom": 11,
    "read":     12,
    "socket":   13,
    "unlink":   14,
    "rename":   15,
}
"""Map a lowercase syscall name to its compact integer ID."""

SYSCALL_ID_TO_NAME: Dict[int, str] = {v: k for k, v in SYSCALL_NAME_TO_ID.items()}
"""Reverse lookup — integer ID → syscall name."""

MONITORED_SYSCALLS: List[str] = list(SYSCALL_NAME_TO_ID.keys())
"""Ordered list of the monitored syscall names."""

NUM_SYSCALLS: int = len(SYSCALL_NAME_TO_ID)
"""Total count of monitored syscall types."""


def syscall_name(syscall_id: int) -> str:
    """Return the human-readable name for a syscall ID.

    Args:
        syscall_id: Integer identifier (0-6).

    Returns:
        Lowercase syscall name, or ``"unknown(<id>)"`` if the ID is not
        in the monitored set.
    """
    return SYSCALL_ID_TO_NAME.get(syscall_id, f"unknown({syscall_id})")


def syscall_id(name: str) -> Optional[int]:
    """Return the integer ID for a syscall name, or ``None`` if unknown.

    Args:
        name: Case-insensitive syscall name (e.g. ``"execve"``).

    Returns:
        Integer ID or ``None``.
    """
    return SYSCALL_NAME_TO_ID.get(name.lower())


# =============================================================================
# Sensitive file paths
# =============================================================================

SENSITIVE_FILE_PATHS: FrozenSet[str] = frozenset({
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/proc/self/mem",
    "/proc/self/maps",
    "/proc/self/environ",
    "/proc/self/exe",
    "/proc/self/fd",
    "~/.ssh/authorized_keys",
    "~/.ssh/id_rsa",
    "~/.ssh/id_ed25519",
    "~/.ssh/known_hosts",
    "~/.ssh/config",
})
"""Absolute (or ``~``-prefixed) paths that are considered security-sensitive.

A file-open event targeting any of these paths increases the suspicion score
of the enclosing behavioural window.
"""

# Precompiled prefixes for fast startswith() checks at runtime.
_SENSITIVE_PREFIXES: List[str] = [
    "/etc/shadow",
    "/etc/sudoers",
    "/proc/self/",
    "/.ssh/",
]


def is_sensitive_path(path: str) -> bool:
    """Return ``True`` if *path* matches a known sensitive location.

    The check covers both exact matches and prefix matches (e.g.
    ``/proc/self/anything``).

    Args:
        path: Absolute file path as reported by the kernel.

    Returns:
        ``True`` when the path is security-sensitive.
    """
    if path in SENSITIVE_FILE_PATHS:
        return True
    for prefix in _SENSITIVE_PREFIXES:
        if path.startswith(prefix):
            return True
    return False
