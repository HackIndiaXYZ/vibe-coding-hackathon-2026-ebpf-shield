"""
core/killer.py — Process termination and forensic logging.

``ProcessKiller`` is the enforcement arm of eBPF-Shield.  When the anomaly
detector flags a PID, the killer:

1. Checks whether the process is *protected* (systemd, sshd, the monitor
   itself, etc.) — protected processes are **never** killed.
2. Collects process metadata via ``psutil`` (if still alive).
3. Sends ``SIGKILL`` (unless ``dry_run=True``).
4. Appends a forensic JSON-Lines record to ``FORENSIC_LOG_PATH``.
"""

from __future__ import annotations

import json
import logging
import os
import signal
import time
from dataclasses import asdict
from pathlib import Path
from typing import FrozenSet, List, Optional, Set

try:
    import psutil
except ImportError as _exc:
    raise ImportError(
        "psutil is required but not installed.  "
        "Run:  pip3 install psutil"
    ) from _exc

try:
    from config import FORENSIC_LOG_PATH, PROTECTED_COMMS
except ImportError:
    # Fallback for isolated testing
    FORENSIC_LOG_PATH = Path("data/forensic_log.jsonl")
    PROTECTED_COMMS: FrozenSet[str] = frozenset()  # type: ignore[no-redef]

from core.consumer import SyscallEvent

logger = logging.getLogger("ebpf-shield.killer")


class ProcessKiller:
    """Terminate anomalous processes and write forensic evidence.

    Args:
        dry_run:        If ``True``, log the would-be kill but do **not**
                        send any signal.
        protected_comms: Extra comm names to protect beyond the config
                         default.
        forensic_path:  Override for the forensic log file path.
    """

    def __init__(
        self,
        dry_run: bool = False,
        protected_comms: Optional[Set[str]] = None,
        forensic_path: Optional[Path] = None,
        blacklist_map = None,
    ) -> None:
        self._dry_run = dry_run
        self._forensic_path = forensic_path or FORENSIC_LOG_PATH
        self._blacklist_map = blacklist_map

        # Merge configured + caller-supplied + self-protection PIDs
        self._protected_comms: FrozenSet[str] = PROTECTED_COMMS | frozenset(
            protected_comms or set()
        )

        # Always protect our own PID tree (self + parent + children)
        self._protected_pids: Set[int] = {0, 1, os.getpid()}
        try:
            self._protected_pids.add(os.getppid())
        except OSError:
            pass
            
        # Protect all system/kernel PIDs below 100
        for p in range(2, 100):
            self._protected_pids.add(p)
        # Also protect all child processes / threads of the monitor
        try:
            me = psutil.Process(os.getpid())
            for child in me.children(recursive=True):
                self._protected_pids.add(child.pid)
            # Protect the entire ancestor chain (sudo → bash → python3)
            parent = me.parent()
            while parent is not None:
                self._protected_pids.add(parent.pid)
                parent = parent.parent()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        # Ensure the log directory exists
        self._forensic_path.parent.mkdir(parents=True, exist_ok=True)

        mode = "DRY-RUN" if dry_run else "ARMED"
        logger.info(
            "ProcessKiller initialised [%s]  protected_comms=%s  "
            "protected_pids=%s",
            mode,
            self._protected_comms,
            self._protected_pids,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def kill(
        self,
        pid: int,
        reason: str,
        score: float,
        comm: str = "",
        syscall_chain: Optional[List[SyscallEvent]] = None,
    ) -> bool:
        """Attempt to kill *pid* and log the forensic record.

        Args:
            pid:            Target PID.
            reason:         Human-readable anomaly description.
            score:          Isolation Forest anomaly score.
            comm:           Process comm name (used for protection check).
            syscall_chain:  The syscall window that triggered the alert.

        Returns:
            ``True`` if the process was killed (or would have been, in
            dry-run mode).  ``False`` if it was protected or already dead.
        """
        # ----- Protection checks -----
        if pid in self._protected_pids:
            logger.warning(
                "Refusing to kill PID %d — it is a protected PID.", pid
            )
            self._log_forensic(pid, comm, score, reason, syscall_chain, "PROTECTED_PID")
            return False

        local_pid = self._translate_to_local_pid(pid)
        effective_comm = comm or self._resolve_comm(local_pid)

        if effective_comm in self._protected_comms or "Relay" in effective_comm:
            logger.warning(
                "Refusing to kill PID %d (%s) — protected comm.",
                pid,
                effective_comm,
            )
            self._log_forensic(
                pid, effective_comm, score, reason, syscall_chain, "PROTECTED_COMM"
            )
            return False

        # ----- Gather pre-kill metadata -----
        proc_info = self._gather_proc_info(local_pid)

        # ----- Kill -----
        if self._dry_run:
            logger.warning(
                "[DRY-RUN] Would kill PID %d (%s)  score=%.4f  reason=%s",
                pid,
                effective_comm,
                score,
                reason,
            )
            self._log_forensic(
                pid, effective_comm, score, reason, syscall_chain, "DRY_RUN",
                proc_info=proc_info,
            )
            return True

        try:
            # 1. Update eBPF Map for instant kernel-level blocking
            map_updated = False
            if self._blacklist_map is not None:
                import ctypes
                try:
                    self._blacklist_map[ctypes.c_uint32(pid)] = ctypes.c_uint32(1)
                    map_updated = True
                except Exception as map_exc:
                    logger.error("Failed to update eBPF blacklist map for PID %d: %s", pid, map_exc)

            # 2. Issue user-space SIGKILL as a fallback
            logger.critical("MY PID: %d, ABOUT TO KILL LOCAL PID %d (GLOBAL %d) (%s)", os.getpid(), local_pid, pid, effective_comm)
            os.kill(local_pid, signal.SIGKILL)
            
            logger.critical(
                "KILLED PID %d (%s)  score=%.4f  reason=%s",
                pid,
                effective_comm,
                score,
                reason,
            )
            self._log_forensic(
                pid, effective_comm, score, reason, syscall_chain, "KILLED",
                proc_info=proc_info,
            )
            return True
        except ProcessLookupError:
            logger.info("PID %d already dead before SIGKILL.", pid)
            self._log_forensic(
                pid, effective_comm, score, reason, syscall_chain, "ALREADY_DEAD"
            )
            # If we updated the in-kernel map, the kernel may have instantly killed it 
            # before os.kill() could fire. Treat it as a successful kill!
            if map_updated:
                return True
            return False
        except PermissionError:
            logger.error(
                "Permission denied killing PID %d — are we root?", pid
            )
            self._log_forensic(
                pid, effective_comm, score, reason, syscall_chain, "EPERM"
            )
            return False
        except OSError as exc:
            logger.error("os.kill(%d) failed: %s", pid, exc)
            self._log_forensic(
                pid, effective_comm, score, reason, syscall_chain, f"ERROR:{exc}"
            )
            return False

    # ------------------------------------------------------------------
    # Forensic logging
    # ------------------------------------------------------------------

    def _log_forensic(
        self,
        pid: int,
        comm: str,
        score: float,
        reason: str,
        syscall_chain: Optional[List[SyscallEvent]],
        action: str,
        proc_info: Optional[dict] = None,
    ) -> None:
        """Append a single JSON-Lines record to the forensic log."""
        chain_serialised: List[dict] = []
        if syscall_chain:
            chain_serialised = [asdict(e) for e in syscall_chain]

        record = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "timestamp_unix": time.time(),
            "pid": pid,
            "comm": comm,
            "score": round(score, 6),
            "reason": reason,
            "action": action,
            "syscall_chain": chain_serialised,
        }

        if proc_info:
            record["proc_info"] = proc_info

        try:
            with open(self._forensic_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, default=str) + "\n")
        except OSError as exc:
            logger.error("Failed to write forensic log: %s", exc)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _translate_to_local_pid(target_pid: int) -> int:
        """Attempt to translate a global PID to a local namespace PID."""
        # If the target_pid is valid in the current namespace, just return it.
        try:
            os.kill(target_pid, 0)
            return target_pid
        except ProcessLookupError:
            pass
            
        # Scan /proc for NSpid mapping
        try:
            for d in os.listdir("/proc"):
                if d.isdigit():
                    try:
                        with open(f"/proc/{d}/status", "r") as f:
                            for line in f:
                                if line.startswith("NSpid:"):
                                    parts = line.strip().split()
                                    if len(parts) >= 3 and str(target_pid) in parts:
                                        # Found it! The first number is global, last is local
                                        return int(d)
                                    break
                    except (OSError, FileNotFoundError):
                        continue
        except OSError:
            pass
            
        return target_pid  # Fallback to the original if translation fails

    @staticmethod
    def _resolve_comm(pid: int) -> str:
        """Best-effort comm lookup via psutil."""
        try:
            proc = psutil.Process(pid)
            return proc.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return ""

    @staticmethod
    def _gather_proc_info(pid: int) -> Optional[dict]:
        """Snapshot process metadata before killing.

        Returns ``None`` if the process is gone or inaccessible.
        """
        try:
            proc = psutil.Process(pid)
            with proc.oneshot():
                return {
                    "name": proc.name(),
                    "exe": proc.exe(),
                    "cmdline": proc.cmdline(),
                    "cwd": proc.cwd(),
                    "username": proc.username(),
                    "create_time": proc.create_time(),
                    "ppid": proc.ppid(),
                    "status": proc.status(),
                    "num_threads": proc.num_threads(),
                }
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None
