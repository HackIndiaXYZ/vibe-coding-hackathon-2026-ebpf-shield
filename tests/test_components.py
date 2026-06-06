"""
tests/test_components.py — Unit tests for eBPF-Shield components.

Tests the pure-Python logic (config, syscall_map, consumer, killer) without
requiring a Linux kernel or BCC.  Run with:

    python -m pytest tests/test_components.py -v

or simply:

    python tests/test_components.py
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


# ============================================================================
# Test: config.py
# ============================================================================

class TestConfig(unittest.TestCase):
    """Verify config module constants and paths."""

    def test_window_seconds_positive(self) -> None:
        from config import WINDOW_SECONDS
        self.assertGreater(WINDOW_SECONDS, 0)

    def test_anomaly_threshold_negative(self) -> None:
        from config import ANOMALY_THRESHOLD
        self.assertLess(ANOMALY_THRESHOLD, 0)

    def test_contamination_in_range(self) -> None:
        from config import CONTAMINATION
        self.assertGreater(CONTAMINATION, 0)
        self.assertLess(CONTAMINATION, 1)

    def test_data_paths_under_data_dir(self) -> None:
        from config import DATA_DIR, MODEL_PATH, SCALER_PATH
        self.assertTrue(str(MODEL_PATH).startswith(str(DATA_DIR)))
        self.assertTrue(str(SCALER_PATH).startswith(str(DATA_DIR)))

    def test_protected_comms_contains_systemd(self) -> None:
        from config import PROTECTED_COMMS
        self.assertIn("systemd", PROTECTED_COMMS)
        self.assertIn("sshd", PROTECTED_COMMS)

    def test_syscall_constants(self) -> None:
        from config import (
            SYSCALL_EXECVE, SYSCALL_OPENAT, SYSCALL_CONNECT,
            SYSCALL_PTRACE, SYSCALL_SETUID, SYSCALL_CLONE, SYSCALL_WRITE,
            SYSCALL_MPROTECT, SYSCALL_MMAP, SYSCALL_EXECVEAT,
            SYSCALL_SENDTO, SYSCALL_RECVFROM, SYSCALL_READ,
            SYSCALL_SOCKET, SYSCALL_UNLINK, SYSCALL_RENAME,
            NUM_SYSCALLS,
        )
        ids = {SYSCALL_EXECVE, SYSCALL_OPENAT, SYSCALL_CONNECT,
               SYSCALL_PTRACE, SYSCALL_SETUID, SYSCALL_CLONE, SYSCALL_WRITE,
               SYSCALL_MPROTECT, SYSCALL_MMAP, SYSCALL_EXECVEAT,
               SYSCALL_SENDTO, SYSCALL_RECVFROM, SYSCALL_READ,
               SYSCALL_SOCKET, SYSCALL_UNLINK, SYSCALL_RENAME}
        self.assertEqual(len(ids), 16, "Syscall IDs must be unique")
        self.assertEqual(NUM_SYSCALLS, 16)

    def test_syscall_hooks_length(self) -> None:
        from config import SYSCALL_HOOKS
        self.assertEqual(len(SYSCALL_HOOKS), 16)


# ============================================================================
# Test: ebpf/syscall_map.py
# ============================================================================

class TestSyscallMap(unittest.TestCase):
    """Verify bidirectional syscall mappings."""

    def test_name_to_id_complete(self) -> None:
        from ebpf.syscall_map import SYSCALL_NAME_TO_ID
        expected = {"execve", "openat", "connect", "ptrace",
                    "setuid", "clone", "write", "mprotect", "mmap",
                    "execveat", "sendto", "recvfrom", "read",
                    "socket", "unlink", "rename"}
        self.assertEqual(set(SYSCALL_NAME_TO_ID.keys()), expected)

    def test_id_to_name_roundtrip(self) -> None:
        from ebpf.syscall_map import SYSCALL_NAME_TO_ID, SYSCALL_ID_TO_NAME
        for name, sid in SYSCALL_NAME_TO_ID.items():
            self.assertEqual(SYSCALL_ID_TO_NAME[sid], name)

    def test_syscall_name_helper(self) -> None:
        from ebpf.syscall_map import syscall_name
        self.assertEqual(syscall_name(0), "execve")
        self.assertEqual(syscall_name(999), "unknown(999)")

    def test_syscall_id_helper(self) -> None:
        from ebpf.syscall_map import syscall_id
        self.assertEqual(syscall_id("CONNECT"), 2)
        self.assertIsNone(syscall_id("nonexistent"))

    def test_sensitive_paths(self) -> None:
        from ebpf.syscall_map import is_sensitive_path
        self.assertTrue(is_sensitive_path("/etc/shadow"))
        self.assertTrue(is_sensitive_path("/proc/self/maps"))
        self.assertTrue(is_sensitive_path("/proc/self/environ"))
        self.assertFalse(is_sensitive_path("/tmp/hello.txt"))


# ============================================================================
# Test: core/consumer.py
# ============================================================================

class TestEventConsumer(unittest.TestCase):
    """Verify sliding-window logic."""

    @staticmethod
    def _make_event(pid: int = 100, syscall_id: int = 1,
                    ts_ns: int = 0) -> "SyscallEvent":
        from core.consumer import SyscallEvent
        return SyscallEvent(
            pid=pid, ppid=1, uid=1000, syscall_id=syscall_id,
            timestamp_ns=ts_ns, comm="test", arg="/bin/sh",
        )

    def test_ingest_returns_none_below_min(self) -> None:
        from core.consumer import EventConsumer
        ec = EventConsumer(window_seconds=2.0, min_events=3)
        # Use OPENAT (1) instead of EXECVE (0) to avoid immediate return
        e1 = self._make_event(syscall_id=1, ts_ns=1_000_000_000)
        e2 = self._make_event(syscall_id=1, ts_ns=1_500_000_000)
        self.assertIsNone(ec.ingest(e1))
        self.assertIsNone(ec.ingest(e2))

    def test_ingest_returns_window_at_min(self) -> None:
        from core.consumer import EventConsumer
        ec = EventConsumer(window_seconds=2.0, min_events=3)
        for i in range(3):
            result = ec.ingest(self._make_event(ts_ns=1_000_000_000 + i * 100_000_000))
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 3)

    def test_old_events_pruned(self) -> None:
        from core.consumer import EventConsumer
        ec = EventConsumer(window_seconds=1.0, min_events=2)
        # Use OPENAT (1) instead of EXECVE (0) to avoid immediate return
        e1 = self._make_event(syscall_id=1, ts_ns=1_000_000_000)
        e2 = self._make_event(syscall_id=1, ts_ns=3_000_000_000)  # 2 seconds later
        ec.ingest(e1)
        result = ec.ingest(e2)
        # e1 should be pruned (outside 1s window)
        self.assertIsNone(result)  # only 1 event in window

    def test_different_pids_independent(self) -> None:
        from core.consumer import EventConsumer
        ec = EventConsumer(window_seconds=5.0, min_events=2)
        ec.ingest(self._make_event(pid=100, ts_ns=1_000_000_000))
        ec.ingest(self._make_event(pid=200, ts_ns=1_000_000_000))
        # Neither PID has 2 events yet
        self.assertEqual(ec.active_pids, 2)

    def test_get_all_windows(self) -> None:
        from core.consumer import EventConsumer
        ec = EventConsumer(window_seconds=5.0, min_events=1)
        ec.ingest(self._make_event(pid=10, ts_ns=1_000_000_000))
        ec.ingest(self._make_event(pid=20, ts_ns=1_000_000_000))
        windows = ec.get_all_windows()
        self.assertIn(10, windows)
        self.assertIn(20, windows)

    def test_clear(self) -> None:
        from core.consumer import EventConsumer
        ec = EventConsumer()
        ec.ingest(self._make_event(ts_ns=1_000_000_000))
        ec.clear()
        self.assertEqual(ec.active_pids, 0)


# ============================================================================
# Test: core/killer.py
# ============================================================================

class TestProcessKiller(unittest.TestCase):
    """Verify protection logic and forensic logging (dry-run)."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.mkdtemp()
        self._forensic = Path(self._tmpdir) / "forensic.jsonl"

    def _make_killer(self, dry_run: bool = True) -> "ProcessKiller":
        from core.killer import ProcessKiller
        return ProcessKiller(dry_run=dry_run, forensic_path=self._forensic)

    def test_refuses_own_pid(self) -> None:
        killer = self._make_killer()
        result = killer.kill(os.getpid(), "test", -1.0)
        self.assertFalse(result)

    def test_refuses_protected_comm(self) -> None:
        killer = self._make_killer()
        result = killer.kill(99999, "test", -1.0, comm="systemd")
        self.assertFalse(result)

    def test_dry_run_does_not_kill(self) -> None:
        killer = self._make_killer(dry_run=True)
        # Use a PID that doesn't exist — dry_run should still "succeed"
        result = killer.kill(99999, "anomaly detected", -0.8, comm="evil_proc")
        self.assertTrue(result)

    def test_forensic_log_written(self) -> None:
        killer = self._make_killer(dry_run=True)
        killer.kill(99999, "test reason", -0.75, comm="evil")
        self.assertTrue(self._forensic.exists())
        with open(self._forensic) as fh:
            record = json.loads(fh.readline())
        self.assertEqual(record["pid"], 99999)
        self.assertEqual(record["action"], "DRY_RUN")
        self.assertIn("reason", record)
        self.assertIn("score", record)

    def test_forensic_log_has_syscall_chain(self) -> None:
        from core.consumer import SyscallEvent
        killer = self._make_killer(dry_run=True)
        chain = [
            SyscallEvent(pid=99999, ppid=1, uid=0, syscall_id=0,
                         timestamp_ns=100, comm="evil", arg="/bin/sh"),
        ]
        killer.kill(99999, "chain test", -0.9, comm="evil", syscall_chain=chain)
        with open(self._forensic) as fh:
            record = json.loads(fh.readline())
        self.assertEqual(len(record["syscall_chain"]), 1)
        self.assertEqual(record["syscall_chain"][0]["syscall_id"], 0)


# ============================================================================
# Entry point
# ============================================================================

if __name__ == "__main__":
    unittest.main(verbosity=2)
