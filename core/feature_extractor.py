"""Feature extraction module for eBPF-Shield.

Transforms raw syscall events into a multi-dimensional feature vector
suitable for anomaly detection via IsolationForest.

Feature dimensions (33 total):
  0-14  : Original 15 features (syscall-based)
  15-20 : Fileless malware features
  21-26 : Ransomware features
  27-30 : Lateral movement features
  31-32 : C2 communication features
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Set

import numpy as np


# ---------------------------------------------------------------------------
# Syscall ID constants (mirrors eBPF probe definitions)
# ---------------------------------------------------------------------------
EXECVE:    int = 0
OPENAT:    int = 1
CONNECT:   int = 2
PTRACE:    int = 3
SETUID:    int = 4
CLONE:     int = 5
WRITE:     int = 6
MPROTECT:  int = 7
MMAP:      int = 8
EXECVEAT:  int = 9
SENDTO:    int = 10
RECVFROM:  int = 11
READ:      int = 12
SOCKET:    int = 13
UNLINK:    int = 14
RENAME:    int = 15


# ---------------------------------------------------------------------------
# SyscallEvent — lightweight representation of one kernel event.
# Defined here so the feature extractor has zero coupling to the eBPF
# consumer module (avoids circular imports when consumer imports us).
# ---------------------------------------------------------------------------
@dataclass
class SyscallEvent:
    """A single syscall event captured by the eBPF probe.

    Attributes:
        pid: Process ID that issued the syscall.
        ppid: Parent process ID.
        uid: User ID of the calling process.
        syscall_id: Numeric syscall identifier (see module-level constants).
        timestamp_ns: Kernel timestamp in nanoseconds.
        comm: Process command name (e.g. ``bash``).
        arg: First string argument of the syscall (path, address, etc.).
    """

    pid: int
    ppid: int
    uid: int
    syscall_id: int
    timestamp_ns: int
    comm: str
    arg: str


# ---------------------------------------------------------------------------
# FeatureVector — output of the extraction step.
# ---------------------------------------------------------------------------
FEATURE_NAMES: List[str] = [
    # Original 15 features (0-14)
    "syscall_count",
    "unique_syscalls",
    "execve_count",
    "openat_count",
    "connect_count",
    "ptrace_count",
    "setuid_count",
    "clone_count",
    "write_count",
    "syscall_rate",
    "sensitive_file_access",
    "shell_spawn",
    "uid_change_attempt",
    "syscall_entropy",
    "priv_esc_sequence",
    # Fileless malware features (15-20)
    "memprotect_rx_count",
    "anonymous_mmap_count",
    "fd_based_exec_count",
    "memory_region_toggle_count",
    "fileless_score",
    "fileless_exec",
    # Ransomware features (21-26)
    "unique_file_opens",
    "write_to_new_files",
    "delete_operations",
    "file_extension_diversity",
    "ransom_note_pattern",
    "ransomware_score",
    # Lateral movement features (27-30)
    "ssh_remote_exec",
    "credential_access_count",
    "port_scan_count",
    "lateral_movement_score",
    # C2 communication features (31-32)
    "beacon_periodicity",
    "non_standard_port_count",
]


# ---------------------------------------------------------------------------
# Sensitive-file path fragments and shell binary fragments.
# ---------------------------------------------------------------------------
_SENSITIVE_PATHS: List[str] = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/proc/self/mem",
    ".ssh/id_",
    ".ssh/authorized_keys",
]

_SHELL_BINARIES: List[str] = [
    "/bin/sh",
    "/bin/bash",
]

# Fileless malware patterns
_FILESS_LESS_PATTERNS: FrozenSet[str] = frozenset({
    "/dev/shm", "/dev/mqueue", "/run/shm",
    "/tmp/.mem", "/var/run/.mem",
})

_MEMFD_PATTERNS: FrozenSet[str] = frozenset({
    "memfd:", "/dev/zero", "/dev/urandom",
})

# Ransomware patterns
_RANSOM_EXTENSIONS: FrozenSet[str] = frozenset({
    ".encrypted", ".locked", ".crypto", ".ransom",
    ".wncry", ".wannacry", ".petya", ".bad",
})

_RANSOM_NOTE_PATTERNS: FrozenSet[str] = frozenset({
    "DECRYPT", "RANSOM", "BITCOIN", "PAYMENT", "README",
    "HOW_TO_DECRYPT", "INSTRUCTIONS", "RESTORE_FILES",
})

# Lateral movement patterns
_SSH_BINARIES: FrozenSet[str] = frozenset({
    "/usr/bin/ssh", "/usr/bin/scp", "/usr/bin/rsync",
    "/usr/bin/slogin", "/bin/ssh", "/bin/scp", "/bin/slogin",
})

_SENSITIVE_PROC_PATTERNS: FrozenSet[str] = frozenset({
    "/proc/self/mem", "/proc/1/mem", "/dev/mem", "/dev/kmem",
})

_CREDENTIAL_PATTERNS: FrozenSet[str] = frozenset({
    "/mem", "/kmem", ".ssh/id_rsa", ".ssh/id_ed25519",
})

# C2 patterns
_SUSPICIOUS_TLDS: FrozenSet[str] = frozenset({
    "ru", "cn", "tk", "pw", "cc", "top", "xyz", "info", "su",
})

_NON_STANDARD_PORTS: FrozenSet[int] = frozenset({
    4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337, 12345, 54321,
})


# Helper function for credential access detection
def _is_credential_access_path(path: str) -> bool:
    """Check if path indicates credential access."""
    if not path:
        return False
    path_lower = path.lower()
    # Check for /proc/<pid>/mem patterns
    if path_lower.startswith("/proc/") and "/mem" in path_lower:
        return True
    # Check for /dev/mem or /dev/kmem
    if path_lower.startswith("/dev/mem") or path_lower.startswith("/dev/kmem"):
        return True
    # Check for SSH key patterns
    if ".ssh/id_" in path_lower:
        return True
    return False


@dataclass
class FeatureVector:
    """Extracted feature vector for a single analysis window.

    Attributes:
        pid: Process ID the features belong to.
        comm: Process command name.
        timestamp: Wall-clock timestamp (seconds since epoch).
        features: numpy array of computed features.
        feature_names: Human-readable names for each feature dimension.
        fileless_exec: Boolean indicating fileless execution detected.
    """

    pid: int
    comm: str
    timestamp: float
    features: np.ndarray
    feature_names: List[str] = field(default_factory=lambda: list(FEATURE_NAMES))
    fileless_exec: bool = False
    syscall_sequence: List[int] = field(default_factory=list)


# ---------------------------------------------------------------------------
# FeatureExtractor
# ---------------------------------------------------------------------------
class FeatureExtractor:
    """Compute a multi-dimensional feature vector from a list of :class:`SyscallEvent` s.

    Usage::

        extractor = FeatureExtractor()
        fv = extractor.extract(events)
        print(fv.features)  # ndarray shape (33,)
    """

    FEATURE_NAMES: List[str] = FEATURE_NAMES

    # ------------------------------------------------------------------ #
    # Public API                                                          #
    # ------------------------------------------------------------------ #
    def extract(self, events: List[SyscallEvent]) -> FeatureVector:
        """Extract a feature vector from *events*.

        Args:
            events: A list of :class:`SyscallEvent` objects belonging to the
                same process / analysis window.

        Returns:
            A :class:`FeatureVector` with a 33-element numpy array.

        Raises:
            TypeError: If *events* is not a list.
        """
        if not isinstance(events, list):
            raise TypeError(f"events must be a list, got {type(events).__name__}")

        if len(events) == 0:
            return self._empty_feature_vector()

        # Sort by timestamp to guarantee temporal ordering.
        sorted_events = sorted(events, key=lambda e: e.timestamp_ns)

        # === Original 15 features (0-14) ===
        basic_features = self._extract_basic_features(sorted_events)

        # === Fileless malware features (15-20) ===
        fileless_features = self._extract_fileless_features(sorted_events)

        # === Ransomware features (21-26) ===
        ransomware_features = self._extract_ransomware_features(sorted_events)

        # === Lateral movement features (27-30) ===
        lateral_features = self._extract_lateral_movement_features(sorted_events)

        # === C2 communication features (31-32) ===
        c2_features = self._extract_c2_features(sorted_events)

        # Combine all features
        all_features = np.concatenate([
            basic_features,
            fileless_features,
            ransomware_features,
            lateral_features,
            c2_features,
        ])

        # Use the first event's metadata for the vector envelope.
        first = sorted_events[0]
        return FeatureVector(
            pid=first.pid,
            comm=first.comm,
            timestamp=first.timestamp_ns / 1e9,
            features=all_features,
            feature_names=list(FEATURE_NAMES),
            fileless_exec=bool(fileless_features[5]) if len(fileless_features) > 5 else False,
            syscall_sequence=[e.syscall_id for e in sorted_events]
        )

    # ------------------------------------------------------------------ #
    # Feature extraction helpers                                          #
    # ------------------------------------------------------------------ #
    @staticmethod
    def _extract_basic_features(events: List[SyscallEvent]) -> np.ndarray:
        """Extract the original 15 basic features."""
        sorted_events = sorted(events, key=lambda e: e.timestamp_ns)

        syscall_count = float(len(sorted_events))
        unique_syscalls = float(len({e.syscall_id for e in sorted_events}))
        execve_count = float(sum(1 for e in sorted_events if e.syscall_id == EXECVE))
        openat_count = float(sum(1 for e in sorted_events if e.syscall_id == OPENAT))
        connect_count = float(sum(1 for e in sorted_events if e.syscall_id == CONNECT))
        ptrace_count = float(sum(1 for e in sorted_events if e.syscall_id == PTRACE))
        setuid_count = float(sum(1 for e in sorted_events if e.syscall_id == SETUID))
        clone_count = float(sum(1 for e in sorted_events if e.syscall_id == CLONE))
        write_count = float(sum(1 for e in sorted_events if e.syscall_id == WRITE))

        syscall_rate = FeatureExtractor._compute_syscall_rate(sorted_events, syscall_count)
        sensitive_file_access = FeatureExtractor._compute_sensitive_file_access(sorted_events)
        shell_spawn = FeatureExtractor._compute_shell_spawn(sorted_events)
        uid_change_attempt = 1.0 if setuid_count > 0 else 0.0
        syscall_entropy = FeatureExtractor._compute_entropy(sorted_events)
        priv_esc_sequence = FeatureExtractor._compute_priv_esc_sequence(sorted_events)

        return np.array([
            syscall_count,
            unique_syscalls,
            execve_count,
            openat_count,
            connect_count,
            ptrace_count,
            setuid_count,
            clone_count,
            write_count,
            syscall_rate,
            sensitive_file_access,
            shell_spawn,
            uid_change_attempt,
            syscall_entropy,
            priv_esc_sequence,
        ], dtype=np.float64)

    @staticmethod
    def _extract_fileless_features(events: List[SyscallEvent]) -> np.ndarray:
        """Extract fileless malware detection features (indices 15-20)."""
        sorted_events = sorted(events, key=lambda e: e.timestamp_ns)

        # mprotect PROT_EXEC count
        memprotect_rx_count = 0.0
        # mmap MAP_ANONYMOUS count
        anonymous_mmap_count = 0.0
        # execveat (fd-based execution) count
        fd_based_exec_count = 0.0
        # memory region permission toggles (mprotect RX after write)
        memory_region_toggle_count = 0.0

        # Track memory operations for toggle detection
        write_events: List[int] = []  # timestamps of write events

        fileless_score = 0.0
        fileless_exec = False

        for e in sorted_events:
            if e.syscall_id == MPROTECT:
                memprotect_rx_count += 1.0
                # Check if making memory executable
                if e.arg and "PROT_EXEC" in e.arg.upper():
                    fileless_score += 0.3
                    # Check for memory toggling pattern (prior write within 1s)
                    for ts in write_events:
                        if e.timestamp_ns - ts < 1_000_000_000:  # within 1s
                            memory_region_toggle_count += 1.0
                            fileless_score += 0.4
                            break

            elif e.syscall_id == MMAP:
                anonymous_mmap_count += 1.0
                if e.arg and ("MAP_ANONYMOUS" in (e.arg or "").upper() or "/dev/zero" in (e.arg or "").lower()):
                    fileless_score += 0.2

            elif e.syscall_id == EXECVEAT:
                fd_based_exec_count += 1.0
                fileless_score += 0.3

            elif e.syscall_id == EXECVE:
                if e.arg:
                    arg_lower = e.arg.lower()
                    # Check for fileless patterns
                    if any(p in arg_lower for p in _FILESS_LESS_PATTERNS):
                        fileless_score += 0.5
                        fileless_exec = True
                    if any(p in arg_lower for p in _MEMFD_PATTERNS):
                        fileless_score += 0.5
                        fileless_exec = True
                    # Check for /proc/self/fd execution
                    if "/proc/self/fd" in arg_lower or "/fd/" in arg_lower:
                        fileless_score += 0.4
                        fileless_exec = True

            elif e.syscall_id == WRITE:
                write_events.append(e.timestamp_ns)

        # Cap fileless_score at 1.0
        fileless_score = min(fileless_score, 1.0)

        return np.array([
            memprotect_rx_count,
            anonymous_mmap_count,
            fd_based_exec_count,
            memory_region_toggle_count,
            fileless_score,
            1.0 if fileless_exec else 0.0,
        ], dtype=np.float64)

    @staticmethod
    def _extract_ransomware_features(events: List[SyscallEvent]) -> np.ndarray:
        """Extract ransomware detection features (indices 21-26)."""
        sorted_events = sorted(events, key=lambda e: e.timestamp_ns)

        unique_file_paths: Set[str] = set()
        write_to_new_files = 0.0
        delete_operations = 0.0
        file_extensions: List[str] = []
        ransom_note_pattern = 0.0

        for e in sorted_events:
            if e.syscall_id == OPENAT and e.arg:
                unique_file_paths.add(e.arg)

                # Check for new file creation (simplified - real impl would check flags)
                if any(ext in e.arg.lower() for ext in [".encrypted", ".locked", ".crypto", ".ransom"]):
                    write_to_new_files += 1.0

                # Extract file extension
                if "." in e.arg:
                    ext = e.arg[e.arg.rfind("."):].lower()
                    file_extensions.append(ext)

                # Check for ransom notes
                arg_upper = e.arg.upper()
                if any(pat in arg_upper for pat in _RANSOM_NOTE_PATTERNS):
                    ransom_note_pattern = 1.0

            elif e.syscall_id == WRITE and e.arg:
                # Check if writing a ransom note
                arg_upper = e.arg.upper()
                if any(pat in arg_upper for pat in _RANSOM_NOTE_PATTERNS):
                    ransom_note_pattern = 1.0

            elif e.syscall_id == UNLINK:
                delete_operations += 1.0

            elif e.syscall_id == RENAME:
                # Ransomware may rename files to .encrypted
                delete_operations += 0.5

        # Calculate file extension diversity (entropy)
        file_extension_diversity = 0.0
        if file_extensions:
            from collections import Counter
            ext_counts = Counter(file_extensions)
            total = sum(ext_counts.values())
            probs = [c / total for c in ext_counts.values()]
            file_extension_diversity = float(-sum(p * math.log2(p) for p in probs if p > 0))

        # Ransomware score heuristic
        ransomware_score = 0.0
        if len(unique_file_paths) > 50:
            ransomware_score += 0.4
        if write_to_new_files > 30:
            ransomware_score += 0.3
        if delete_operations > 20:
            ransomware_score += 0.3
        if ransom_note_pattern > 0:
            ransomware_score += 0.5

        ransomware_score = min(ransomware_score, 1.0)

        return np.array([
            float(len(unique_file_paths)),
            write_to_new_files,
            delete_operations,
            file_extension_diversity,
            ransom_note_pattern,
            ransomware_score,
        ], dtype=np.float64)

    @staticmethod
    def _extract_lateral_movement_features(events: List[SyscallEvent]) -> np.ndarray:
        """Extract lateral movement detection features (indices 27-30)."""
        sorted_events = sorted(events, key=lambda e: e.timestamp_ns)

        ssh_remote_exec = 0.0
        credential_access_count = 0.0
        port_scan_count = 0.0
        destination_ports: Set[int] = set()

        for e in sorted_events:
            # SSH remote execution detection
            if e.syscall_id == EXECVE and e.arg:
                arg_lower = e.arg.lower()
                if any(ssh in arg_lower for ssh in _SSH_BINARIES):
                    ssh_remote_exec += 1.0

            # Credential access via /proc/*/mem or /dev/mem
            if e.syscall_id == READ and e.arg:
                if _is_credential_access_path(e.arg):
                    credential_access_count += 1.0

            # SSH key access
            if e.syscall_id == OPENAT and e.arg:
                if any(pat in e.arg for pat in _CREDENTIAL_PATTERNS):
                    credential_access_count += 1.0

            # Port scanning detection (track unique destination ports)
            # Note: In real implementation, we'd correlate connect() with /proc/net/tcp
            # Here we use heuristic based on connect attempts
            if e.syscall_id == CONNECT:
                # Try to parse port from arg (simplified)
                try:
                    if e.arg and e.arg != "":
                        # arg might contain port info
                        destination_ports.add(hash(e.arg) % 65536)
                except (ValueError, TypeError):
                    pass

        # Lateral movement score
        lateral_movement_score = 0.0
        if ssh_remote_exec > 0:
            lateral_movement_score += 0.5
        if credential_access_count > 0:
            lateral_movement_score += 0.4
        if len(destination_ports) > 10:
            lateral_movement_score += 0.3
            port_scan_count = float(len(destination_ports))

        lateral_movement_score = min(lateral_movement_score, 1.0)

        return np.array([
            ssh_remote_exec,
            credential_access_count,
            port_scan_count,
            lateral_movement_score,
        ], dtype=np.float64)

    @staticmethod
    def _extract_c2_features(events: List[SyscallEvent]) -> np.ndarray:
        """Extract C2 communication detection features (indices 31-32)."""
        sorted_events = sorted(events, key=lambda e: e.timestamp_ns)

        # Beacon periodicity - measure variance in connection intervals
        connect_timestamps: List[int] = []
        for e in sorted_events:
            if e.syscall_id == CONNECT:
                connect_timestamps.append(e.timestamp_ns)

        beacon_periodicity = 0.0
        if len(connect_timestamps) >= 3:
            # Calculate inter-arrival times
            intervals = [
                connect_timestamps[i+1] - connect_timestamps[i]
                for i in range(len(connect_timestamps) - 1)
            ]
            if intervals:
                mean_interval = sum(intervals) / len(intervals)
                if mean_interval > 0:
                    # Normalized variance
                    variance = sum((t - mean_interval) ** 2 for t in intervals) / len(intervals)
                    normalized_variance = variance / (mean_interval ** 2)
                    beacon_periodicity = min(normalized_variance, 1.0)

        # Non-standard port connections
        non_standard_port_count = 0.0
        for e in sorted_events:
            if e.syscall_id == CONNECT and e.arg:
                # Check if arg contains suspicious port pattern
                arg_str = str(e.arg).lower()
                # Check for non-standard ports in the argument
                try:
                    for port in _NON_STANDARD_PORTS:
                        if str(port) in arg_str:
                            non_standard_port_count += 1.0
                except (ValueError, TypeError):
                    pass

        return np.array([
            beacon_periodicity,
            non_standard_port_count,
        ], dtype=np.float64)

    # ------------------------------------------------------------------ #
    # Static helpers (original implementation preserved)                #
    # ------------------------------------------------------------------ #
    @staticmethod
    def _empty_feature_vector() -> FeatureVector:
        """Return a zeroed-out feature vector for an empty event list."""
        return FeatureVector(
            pid=0,
            comm="",
            timestamp=0.0,
            features=np.zeros(33, dtype=np.float64),
            feature_names=list(FEATURE_NAMES),
        )

    @staticmethod
    def _compute_syscall_rate(
        events: List[SyscallEvent], count: float
    ) -> float:
        """Compute syscalls-per-second over the event window."""
        if len(events) < 2:
            return 0.0
        span_ns = events[-1].timestamp_ns - events[0].timestamp_ns
        span_s = span_ns / 1e9
        if span_s <= 0:
            return count * 10000.0
        return count / span_s

    @staticmethod
    def _compute_sensitive_file_access(events: List[SyscallEvent]) -> float:
        """Count openat events that target sensitive paths."""
        count = 0.0
        for e in events:
            if e.syscall_id == OPENAT and e.arg:
                arg_lower = e.arg.lower()
                if any(p in arg_lower for p in _SENSITIVE_PATHS):
                    count += 1.0
        return count

    @staticmethod
    def _compute_shell_spawn(events: List[SyscallEvent]) -> float:
        """Count execve events that spawn a shell."""
        count = 0.0
        for e in events:
            if e.syscall_id == EXECVE and e.arg:
                if any(sh in e.arg for sh in _SHELL_BINARIES):
                    count += 1.0
        return count

    @staticmethod
    def _compute_entropy(events: List[SyscallEvent]) -> float:
        """Shannon entropy of syscall-type distribution (bits)."""
        if not events:
            return 0.0
        ids = np.array([e.syscall_id for e in events], dtype=np.int64)
        _, counts = np.unique(ids, return_counts=True)
        probs = counts / counts.sum()
        entropy: float = float(-np.sum(probs * np.log2(probs)))
        return entropy

    @staticmethod
    def _compute_priv_esc_sequence(events: List[SyscallEvent]) -> float:
        """Detect privilege-escalation patterns in temporal order."""
        seen_ptrace = False
        seen_setuid = False
        for e in events:
            if e.syscall_id == PTRACE:
                seen_ptrace = True
            elif e.syscall_id == SETUID:
                if seen_ptrace:
                    return 1.0
                seen_setuid = True
            elif e.syscall_id == EXECVE:
                if seen_setuid:
                    return 1.0
        return 0.0
