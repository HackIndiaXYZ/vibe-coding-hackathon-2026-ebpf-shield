"""
core/consumer.py — Per-PID sliding-window event aggregator.

The ``EventConsumer`` collects ``SyscallEvent`` instances emitted by the eBPF
probes and groups them into fixed-duration windows keyed by PID.  Once a
window contains enough events (≥ 3), it is returned to the caller for
feature extraction and scoring.

This module also defines the canonical ``SyscallEvent`` dataclass used
throughout the user-space side of eBPF-Shield.
"""

from __future__ import annotations

import time
import logging
from dataclasses import dataclass
from typing import Dict, List, Optional

# Import defaults from config — but allow per-instance override.
try:
    from config import WINDOW_SECONDS as _DEFAULT_WINDOW
except ImportError:
    _DEFAULT_WINDOW = 2.0

logger = logging.getLogger("ebpf-shield.consumer")


# =============================================================================
# SyscallEvent — canonical user-space event record
# =============================================================================

@dataclass(frozen=True, slots=True)
class SyscallEvent:
    """Immutable record for a single intercepted syscall.

    Attributes:
        pid:          Process ID of the calling task.
        ppid:         Parent PID.
        uid:          Real UID of the calling task.
        syscall_id:   Compact ID (0-6) — see ``config.SYSCALL_*`` constants.
        timestamp_ns: Kernel monotonic timestamp (nanoseconds).
        comm:         Task comm string (≤ 16 chars).
        arg:          First argument string (≤ 128 chars, best-effort).
    """

    pid: int
    ppid: int
    uid: int
    syscall_id: int
    timestamp_ns: int
    comm: str
    arg: str


# =============================================================================
# EventConsumer
# =============================================================================

class EventConsumer:
    """Sliding-window event aggregator keyed by PID.

    For every arriving event the consumer:

    1. Appends it to the per-PID buffer.
    2. Prunes events older than ``window_seconds``.
    3. If the remaining window has ≥ ``min_events`` entries, returns the
       window snapshot to the caller (for feature extraction).

    Args:
        window_seconds: Duration of the sliding window (seconds).
        min_events:     Minimum number of events before a window is emitted.
    """

    def __init__(
        self,
        window_seconds: float = _DEFAULT_WINDOW,
        min_events: int = 3,
    ) -> None:
        self._window_ns: int = int(window_seconds * 1_000_000_000)
        self._min_events: int = min_events
        self._windows: Dict[int, List[SyscallEvent]] = {}
        logger.debug(
            "EventConsumer initialised: window=%ss  min_events=%d",
            window_seconds,
            min_events,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def ingest(self, event: SyscallEvent) -> Optional[List[SyscallEvent]]:
        """Add an event and return the current window if ready.

        Args:
            event: A ``SyscallEvent`` from the eBPF probe.

        Returns:
            A *snapshot* (shallow copy) of the current window for the event's
            PID if it contains enough events.  Otherwise ``None``.
        """
        pid = event.pid
        if pid not in self._windows:
            self._windows[pid] = []
            
            # Periodically prune stale PIDs (every 100 new PIDs)
            if len(self._windows) % 100 == 0:
                self._prune_stale_pids(event.timestamp_ns)

        window = self._windows[pid]
        window.append(event)

        # Prune old events from this PID's window
        cutoff = event.timestamp_ns - self._window_ns
        while window and window[0].timestamp_ns < cutoff:
            window.pop(0)

        # If window is empty after pruning, we don't delete the PID here
        # (to avoid thrashing if the PID is still active).  Stale PIDs
        # are handled by _prune_stale_pids.

        if len(window) >= self._min_events:
            return list(window)

        return None

    def _prune_stale_pids(self, current_ts_ns: int) -> None:
        """Remove PIDs that haven't sent events in the last window."""
        stale_pids = []
        for pid, window in self._windows.items():
            if not window or (current_ts_ns - window[-1].timestamp_ns) > self._window_ns * 5:
                stale_pids.append(pid)
        
        for pid in stale_pids:
            del self._windows[pid]
            
        if stale_pids:
            logger.debug("Pruned %d stale PIDs from consumer", len(stale_pids))

    def get_all_windows(self) -> Dict[int, List[SyscallEvent]]:
        """Return a copy of every active per-PID window.

        Useful during **training mode** where we want to dump all collected
        behavioural windows at once.

        Returns:
            ``{pid: [SyscallEvent, …]}`` dict (shallow-copied lists).
        """
        return {pid: list(events) for pid, events in self._windows.items()}

    def clear(self) -> None:
        """Drop all buffered events."""
        self._windows.clear()

    @property
    def active_pids(self) -> int:
        """Number of PIDs currently tracked."""
        return len(self._windows)
