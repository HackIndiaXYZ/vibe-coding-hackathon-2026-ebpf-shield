"""
ebpf/probes.py — eBPF probe loader and event dispatcher.

This module is the heart of eBPF-Shield's kernel-level telemetry pipeline.
It embeds a BPF C program (as a Python string) that attaches to seven
``tracepoint/syscalls/sys_enter_*`` hooks, captures a compact ``event``
struct for every invocation, and pushes it to user-space via a perf buffer.

The Python-side ``SyscallProbe`` class compiles the C source through BCC,
opens the perf buffer, and dispatches parsed ``SyscallEvent`` dataclass
instances to a caller-supplied callback.

Requires:
    - Linux kernel ≥ 4.18 with ``CONFIG_BPF_SYSCALL=y``
    - python3-bcc (BCC Python bindings)
    - Root privileges (CAP_BPF + CAP_PERFMON at minimum)
"""

from __future__ import annotations

import ctypes as ct
import logging
import os
import threading
from dataclasses import dataclass, field
from typing import Callable, Optional, Set

# ---------------------------------------------------------------------------
# Graceful import of BCC — give a clear message when running off-target.
# ---------------------------------------------------------------------------
try:
    from bcc import BPF  # type: ignore[import-untyped]
except ImportError as _exc:
    raise ImportError(
        "python3-bcc is required but not installed.  "
        "On Fedora:  sudo dnf install python3-bcc bcc bcc-tools\n"
        "Make sure you are running on a Linux host with a BPF-capable kernel."
    ) from _exc

logger = logging.getLogger("ebpf-shield.probes")

# =============================================================================
# SyscallEvent dataclass — the user-space representation of a kernel event
# =============================================================================

@dataclass(frozen=True, slots=True)
class SyscallEvent:
    """Immutable record produced for every intercepted syscall.

    Attributes:
        pid:          Process ID of the calling task.
        ppid:         Parent PID.
        uid:          Real UID of the calling task.
        syscall_id:   Compact ID (0-6) — see ``config.SYSCALL_*`` constants.
        timestamp_ns: Kernel monotonic timestamp in nanoseconds.
        comm:         Task comm (up to 16 bytes, UTF-8 decoded).
        arg:          First argument string (up to 128 bytes, best-effort).
    """

    pid: int
    ppid: int
    uid: int
    syscall_id: int
    timestamp_ns: int
    comm: str
    arg: str


# =============================================================================
# ctypes mirror of the C ``struct event`` — used to parse the raw perf buffer
# =============================================================================

class _EventCt(ct.Structure):
    """ctypes layout matching the eBPF ``struct event``."""

    _fields_ = [
        ("pid", ct.c_uint32),
        ("ppid", ct.c_uint32),
        ("uid", ct.c_uint32),
        ("syscall_id", ct.c_uint32),
        ("timestamp_ns", ct.c_uint64),
        ("comm", ct.c_char * 16),
        ("arg", ct.c_char * 128),
    ]


# =============================================================================
# Embedded eBPF C program
# =============================================================================

_BPF_PROGRAM: str = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

/* ------------------------------------------------------------------ */
/* Event structure pushed to user-space via perf buffer                */
/* ------------------------------------------------------------------ */
struct event {
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 syscall_id;
    u64 timestamp_ns;
    char comm[16];
    char arg[128];
};

/* Ring output map — massive throughput */
BPF_RINGBUF_OUTPUT(events, 256);

/* Blacklist Map — shared with user-space for instant-kill feedback loop */
BPF_HASH(blacklist, u32, u32);

/* Map to expose the global PID to user-space */
BPF_ARRAY(my_pid_map, u32, 1);

/* Per-PID rate limiter for high-volume syscalls (read/write/sendto/recvfrom) */
/* Value = last emit timestamp in nanoseconds */
BPF_HASH(rate_limit, u32, u64);

/* Rate limit interval: 100ms in nanoseconds */
#define RATE_LIMIT_NS 100000000ULL

/* Helper function to instantly kill blacklisted PIDs */
static __always_inline int check_blacklist(void) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 *is_blocked = blacklist.lookup(&pid);
    if (is_blocked && *is_blocked == 1) {
        bpf_send_signal(9);
        return 1;
    }
    return 0;
}

/* Rate limiter: returns 1 if this PID should be skipped (too recent) */
static __always_inline int check_rate_limit(void) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 now = bpf_ktime_get_ns();
    u64 *last = rate_limit.lookup(&pid);
    if (last && (now - *last) < RATE_LIMIT_NS) {
        return 1;  /* skip — emitted too recently */
    }
    rate_limit.update(&pid, &now);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Helper: populate shared fields of struct event                     */
/* ------------------------------------------------------------------ */
static __always_inline void fill_event(struct event *e, u32 syscall_id) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 uid_gid  = bpf_get_current_uid_gid();

    e->pid          = pid_tgid >> 32;
    e->uid          = uid_gid & 0xFFFFFFFF;
    e->syscall_id   = syscall_id;
    e->timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    /* ppid — walk task_struct */
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->ppid = task->real_parent->tgid;
}

/* ================================================================== */
/* Tracepoint handlers — one per monitored syscall                    */
/* ================================================================== */

TRACEPOINT_PROBE(syscalls, sys_enter_getpid) {
    u32 key = 0;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    my_pid_map.update(&key, &pid);
    return 0;
}

/* 0 — execve  */
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    if (check_blacklist()) return 0;
    struct event e = {};
    fill_event(&e, 0);
    bpf_probe_read_user_str(e.arg, sizeof(e.arg), args->filename);
    
    // SHIFT-LEFT HEURISTIC: Fileless / memfd execution
    if (e.arg[0] == '/' && e.arg[1] == 'd' && e.arg[2] == 'e' && e.arg[3] == 'v' && e.arg[4] == '/' && e.arg[5] == 's' && e.arg[6] == 'h' && e.arg[7] == 'm') {
        bpf_send_signal(9); // Instant Kill!
        return 0;
    }
    
    events.ringbuf_output(&e, sizeof(e), 0);
    return 0;
}

/* 1 — openat */
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    if (check_blacklist()) return 0;
    struct event e = {};
    fill_event(&e, 1);
    bpf_probe_read_user_str(e.arg, sizeof(e.arg), args->filename);
    events.ringbuf_output(&e, sizeof(e), 0);
    return 0;
}

/* 2 — connect */
TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    if (check_blacklist()) return 0;
    struct event e = {};
    fill_event(&e, 2);
    e.arg[0] = '\0';
    events.ringbuf_output(&e, sizeof(e), 0);
    return 0;
}

/* 3 — ptrace (Tracepoint) */
TRACEPOINT_PROBE(syscalls, sys_enter_ptrace) {
    if (check_blacklist()) return 0;
    
    // SHIFT-LEFT HEURISTIC: Unconditional ban on ptrace for non-root users
    u64 uid_gid  = bpf_get_current_uid_gid();
    u32 uid = uid_gid & 0xFFFFFFFF;
    if (uid != 0) {
        bpf_send_signal(9); // Instant Kill Process Injection!
        return 0;
    }

    struct event e = {};
    fill_event(&e, 3);
    e.arg[0] = '\0';
    events.ringbuf_output(&e, sizeof(e), 0);
    return 0;
}

/* Fallback kprobe for ptrace (WSL2 sometimes drops tracepoints) */
int kprobe____x64_sys_ptrace(struct pt_regs *ctx) {
    if (check_blacklist()) return 0;
    
    // SHIFT-LEFT HEURISTIC
    u64 uid_gid  = bpf_get_current_uid_gid();
    u32 uid = uid_gid & 0xFFFFFFFF;
    if (uid != 0) {
        bpf_send_signal(9); // Instant Kill Process Injection!
        return 0;
    }

    struct event e = {};
    fill_event(&e, 3);
    e.arg[0] = '\0';
    events.ringbuf_output(&e, sizeof(e), 0);
    return 0;
}

/* 4 — setuid */
TRACEPOINT_PROBE(syscalls, sys_enter_setuid) {
    if (check_blacklist()) return 0;
    struct event e = {};
    fill_event(&e, 4);
    e.arg[0] = '\0';
    events.ringbuf_output(&e, sizeof(e), 0);
    return 0;
}

/* 5 — clone */
TRACEPOINT_PROBE(syscalls, sys_enter_clone) {
    if (check_blacklist()) return 0;
    struct event e = {};
    fill_event(&e, 5);
    e.arg[0] = '\0';
    events.ringbuf_output(&e, sizeof(e), 0);
    return 0;
}

/* 6 — write (rate-limited: high volume) */
TRACEPOINT_PROBE(syscalls, sys_enter_write) {
    if (check_blacklist()) return 0;
    if (check_rate_limit()) return 0;
    struct event e = {};
    fill_event(&e, 6);
    bpf_probe_read_user_str(e.arg, sizeof(e.arg), (void *)args->buf);
    events.ringbuf_output(&e, sizeof(e), 0);
    return 0;
}

/* 7 — mprotect */
TRACEPOINT_PROBE(syscalls, sys_enter_mprotect) {
    if (check_blacklist()) return 0;
    struct event e = {};
    fill_event(&e, 7);
    e.arg[0] = '\0';
    events.ringbuf_output(&e, sizeof(e), 0);
    return 0;
}

/* 8 — mmap */
TRACEPOINT_PROBE(syscalls, sys_enter_mmap) {
    if (check_blacklist()) return 0;
    struct event e = {};
    fill_event(&e, 8);
    e.arg[0] = '\0';
    events.ringbuf_output(&e, sizeof(e), 0);
    return 0;
}

/* 9 — execveat */
TRACEPOINT_PROBE(syscalls, sys_enter_execveat) {
    if (check_blacklist()) return 0;
    struct event e = {};
    fill_event(&e, 9);
    bpf_probe_read_user_str(e.arg, sizeof(e.arg), (void *)args->filename);
    events.ringbuf_output(&e, sizeof(e), 0);
    return 0;
}

/* 10 — sendto (rate-limited: high volume) */
TRACEPOINT_PROBE(syscalls, sys_enter_sendto) {
    if (check_blacklist()) return 0;
    if (check_rate_limit()) return 0;
    struct event e = {};
    fill_event(&e, 10);
    e.arg[0] = '\0';
    events.ringbuf_output(&e, sizeof(e), 0);
    return 0;
}

/* 11 — recvfrom (rate-limited: high volume) */
TRACEPOINT_PROBE(syscalls, sys_enter_recvfrom) {
    if (check_blacklist()) return 0;
    if (check_rate_limit()) return 0;
    struct event e = {};
    fill_event(&e, 11);
    e.arg[0] = '\0';
    events.ringbuf_output(&e, sizeof(e), 0);
    return 0;
}

/* 12 — read (rate-limited: high volume) */
TRACEPOINT_PROBE(syscalls, sys_enter_read) {
    if (check_blacklist()) return 0;
    if (check_rate_limit()) return 0;
    struct event e = {};
    fill_event(&e, 12);
    e.arg[0] = '\0';
    events.ringbuf_output(&e, sizeof(e), 0);
    return 0;
}

/* 13 — socket */
TRACEPOINT_PROBE(syscalls, sys_enter_socket) {
    if (check_blacklist()) return 0;
    struct event e = {};
    fill_event(&e, 13);
    e.arg[0] = '\0';
    events.ringbuf_output(&e, sizeof(e), 0);
    return 0;
}

/* 14 — unlink */
TRACEPOINT_PROBE(syscalls, sys_enter_unlink) {
    if (check_blacklist()) return 0;
    struct event e = {};
    fill_event(&e, 14);
    bpf_probe_read_user_str(e.arg, sizeof(e.arg), (void *)args->pathname);
    events.ringbuf_output(&e, sizeof(e), 0);
    return 0;
}

/* 15 — rename */
TRACEPOINT_PROBE(syscalls, sys_enter_rename) {
    if (check_blacklist()) return 0;
    struct event e = {};
    fill_event(&e, 15);
    bpf_probe_read_user_str(e.arg, sizeof(e.arg), (void *)args->oldname);
    events.ringbuf_output(&e, sizeof(e), 0);
    return 0;
}
"""

# =============================================================================
# SyscallProbe — Python-side BCC loader and event dispatcher
# =============================================================================

class SyscallProbe:
    """Load the eBPF program, attach tracepoints, and dispatch events.

    Args:
        callback:     Function called with each parsed ``SyscallEvent``.
        exclude_pids: Optional set of PIDs whose events should be silently
                      dropped (e.g. the monitor's own PID).
    """

    def __init__(
        self,
        callback: Callable[[SyscallEvent], None],
        exclude_pids: Optional[Set[int]] = None,
    ) -> None:
        self._callback = callback
        self._exclude_pids: Set[int] = exclude_pids or set()
        self._running = threading.Event()
        self._bpf: Optional[BPF] = None
        self._lost_samples: int = 0

        logger.info("Compiling eBPF program …")
        try:
            self._bpf = BPF(text=_BPF_PROGRAM)
            
            # Extract our global PID from the kernel's perspective
            os.getpid()  # Trigger the tracepoint
            global_pid = self._bpf["my_pid_map"][ct.c_uint32(0)].value
            self.global_pid = global_pid if global_pid else os.getpid()
            
            if self.global_pid != os.getpid():
                logger.info("Namespace detected: Local PID %d -> Global PID %d", os.getpid(), self.global_pid)
                self._exclude_pids.add(self.global_pid)

        except Exception as exc:
            logger.error("Failed to compile eBPF program: %s", exc)
            raise RuntimeError(
                "BPF compilation failed.  Are you running as root on a "
                "BPF-capable kernel with kernel-devel installed?"
            ) from exc

        # Attach the ring buffer
        self._bpf["events"].open_ring_buffer(self._handle_event)
        logger.info("eBPF tracepoints attached — ring buffer probe ready.")

    @property
    def blacklist_map(self):
        """Return the BPF blacklist map object."""
        return self._bpf["blacklist"]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Enter a blocking poll loop, dispatching events until ``stop()``."""
        self._running.set()
        logger.info("Starting ring-buffer poll loop …")
        try:
            while self._running.is_set():
                self._bpf.ring_buffer_poll(timeout=100)
                self._bpf.ring_buffer_consume()
        except KeyboardInterrupt:
            logger.info("KeyboardInterrupt — stopping probe.")
        finally:
            self.stop()

    def stop(self) -> None:
        """Signal the poll loop to exit and clean up BPF resources."""
        self._running.clear()
        logger.info("eBPF probe stopped.")

    # ------------------------------------------------------------------
    # Internal ring-buffer callback
    # ------------------------------------------------------------------

    def _handle_event(self, ctx: ct.c_void_p, data: ct.c_void_p, size: int) -> None:
        """Parse a raw ring-buffer sample into a ``SyscallEvent``.

        Args:
            ctx:  BPF context (ignored).
            data: Pointer to the raw ``struct event`` bytes.
            size: Byte length of the sample.
        """
        try:
            raw = ct.cast(data, ct.POINTER(_EventCt)).contents

            pid = raw.pid

            # Fast-path: skip our own events
            if pid in self._exclude_pids:
                return

            event = SyscallEvent(
                pid=pid,
                ppid=raw.ppid,
                uid=raw.uid,
                syscall_id=raw.syscall_id,
                timestamp_ns=raw.timestamp_ns,
                comm=raw.comm.decode("utf-8", errors="replace").rstrip("\x00"),
                arg=raw.arg.decode("utf-8", errors="replace").rstrip("\x00"),
            )

            self._callback(event)

        except Exception:  # noqa: BLE001 — never crash the poll loop
            logger.exception("Error handling ring-buffer event")

    # ------------------------------------------------------------------
    # Context-manager support
    # ------------------------------------------------------------------

    def __enter__(self) -> "SyscallProbe":
        return self

    def __exit__(self, *_exc_info: object) -> None:
        self.stop()
