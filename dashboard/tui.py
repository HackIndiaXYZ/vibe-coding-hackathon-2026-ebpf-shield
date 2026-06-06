#!/usr/bin/env python3
"""
dashboard/tui.py — Rich-based live terminal dashboard for eBPF-Shield.

Modular architecture splitting the UI into separate panel components.
"""

from __future__ import annotations

import os
import sys
import time
import threading
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional

from rich import box
from rich.align import Align
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# Try to load PROTECTED_COMMS from config if available (for verbose status panel)
try:
    # Handle standalone execution path
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
    from config import PROTECTED_COMMS
except ImportError:
    PROTECTED_COMMS = frozenset({"systemd", "sudo", "bash"})


# ── Data classes ─────────────────────────────────────────────────────────────

@dataclass
class SyscallEvent:
    timestamp: str
    pid: int
    comm: str
    syscall_name: str
    arg: str = ""

@dataclass
class ProcessEntry:
    pid: int
    comm: str
    score: float
    status: str
    last_seen: str = ""

@dataclass
class ThreatEntry:
    timestamp: str
    pid: int
    comm: str
    score: float
    reason: str
    chain: list[str] = field(default_factory=list)


# ── Color utilities ──────────────────────────────────────────────────────────

SUSPICIOUS_SYSCALLS = {
    "ptrace", "setuid", "setgid", "setreuid", "setregid",
    "setresuid", "setresgid", "capset", "init_module",
    "finit_module", "delete_module", "pivot_root", "mount",
    "umount2", "swapon", "swapoff", "reboot", "sethostname",
    "setdomainname", "kexec_load", "perf_event_open",
}

def _score_color(score: float) -> str:
    if score < 0.3: return "green"
    if score < 0.5: return "dark_green"
    if score < 0.65: return "yellow"
    if score < 0.8: return "dark_orange"
    return "bold red"

def _syscall_style(name: str) -> str:
    return "bold yellow" if name in SUSPICIOUS_SYSCALLS else "green"

def _status_icon(status: str) -> str:
    mapping = {
        "safe": "[green]✅ SAFE[/green]",
        "warning": "[yellow]⚠️  WARN[/yellow]",
        "threat": "[bold red]🔴 THREAT[/bold red]",
        "killed": "[bold red]💀 KILLED[/bold red]",
    }
    return mapping.get(status, status)


# ── Modular UI Components ────────────────────────────────────────────────────

class HeaderPanel:
    @staticmethod
    def render(mode: str) -> Panel:
        title = Text()
        title.append("  ⬡ ", style="bold cyan")
        title.append("eBPF", style="bold bright_cyan")
        title.append("-", style="dim white")
        title.append("SHIELD", style="bold bright_white")
        title.append("  v0.1", style="dim cyan")
        title.append("  —  ", style="dim white")
        title.append("Kernel AI Security Monitor", style="italic bright_cyan")

        mode_style = {
            "DETECTING": "bold white on red",
            "TRAINING": "bold white on dark_green",
            "DRY-RUN": "bold white on dark_orange",
        }.get(mode, "bold white on blue")
        
        title.append("      ")
        title.append(f"  {mode}  ", style=mode_style)

        return Panel(Align.center(title), style="bright_cyan", box=box.DOUBLE_EDGE, padding=(0, 1))

class SyscallFeedPanel:
    @staticmethod
    def render(feed: deque, display_count: int) -> Panel:
        table = Table(show_header=True, header_style="bold cyan", box=box.SIMPLE_HEAVY, expand=True, padding=(0, 1), show_edge=False)
        table.add_column("TIME", style="dim", width=12, no_wrap=True)
        table.add_column("PID", justify="right", width=7, no_wrap=True)
        table.add_column("PROCESS", width=14, no_wrap=True)
        table.add_column("SYSCALL", width=14, no_wrap=True)
        table.add_column("ARG", ratio=1, no_wrap=True)

        visible = list(feed)[-display_count:]
        for ev in visible:
            table.add_row(
                Text(ev.timestamp, style="dim white"),
                Text(str(ev.pid), style="bright_white"),
                Text(ev.comm[:14], style="bright_white"),
                Text(ev.syscall_name, style=_syscall_style(ev.syscall_name)),
                Text(ev.arg[:30] if ev.arg else "", style="dim"),
            )

        return Panel(table, title="[bold bright_cyan]📡 LIVE SYSCALL FEED[/bold bright_cyan]", border_style="cyan", box=box.ROUNDED, padding=(0, 0))

class ProcessMonitorPanel:
    @staticmethod
    def render(processes: dict, lock: threading.Lock, display_count: int) -> Panel:
        table = Table(show_header=True, header_style="bold cyan", box=box.SIMPLE_HEAVY, expand=True, padding=(0, 1), show_edge=False)
        table.add_column("PID", justify="right", width=7, no_wrap=True)
        table.add_column("PROCESS", width=14, no_wrap=True)
        table.add_column("AI SCORE", justify="center", width=9, no_wrap=True)
        table.add_column("▓ BAR", width=12, no_wrap=True)
        table.add_column("STATUS", width=14, no_wrap=True)
        table.add_column("SEEN", style="dim", width=9, no_wrap=True)

        with lock:
            sorted_procs = sorted(
                processes.values(),
                key=lambda p: (0 if p.status in ("threat", "killed") else 1, -p.score),
            )

        for proc in sorted_procs[:display_count]:
            color = _score_color(proc.score)
            filled = int(proc.score * 10)
            bar_text = Text()
            bar_text.append("▓" * filled, style=color)
            bar_text.append("░" * (10 - filled), style="dim")
            
            # Show a shield icon if process is inherently protected (verbose feature)
            comm_display = f"🛡️ {proc.comm[:12]}" if proc.comm in PROTECTED_COMMS else proc.comm[:14]

            table.add_row(
                Text(str(proc.pid), style="bright_white"),
                Text(comm_display, style="bright_white"),
                Text(f"{proc.score:.2f}", style=color),
                bar_text,
                Text.from_markup(_status_icon(proc.status)),
                Text(proc.last_seen, style="dim white"),
            )

        return Panel(table, title="[bold bright_cyan]🖥  PROCESS MONITOR (VERBOSE)[/bold bright_cyan]", border_style="cyan", box=box.ROUNDED, padding=(0, 0))

class ThreatLogPanel:
    @staticmethod
    def render(threats: deque, display_count: int) -> Panel:
        table = Table(show_header=True, header_style="bold red", box=box.SIMPLE_HEAVY, expand=True, padding=(0, 1), show_edge=False)
        table.add_column("TIME", style="dim", width=9, no_wrap=True)
        table.add_column("PID", justify="right", width=7, no_wrap=True)
        table.add_column("PROCESS", width=12, no_wrap=True)
        table.add_column("SCORE", justify="center", width=7, no_wrap=True)
        table.add_column("REASON", ratio=1)
        table.add_column("CHAIN", ratio=1, no_wrap=True)

        visible = list(threats)[-display_count:]
        for t in visible:
            chain_text = Text()
            for i, syscall in enumerate(t.chain):
                if i > 0:
                    chain_text.append(" → ", style="dim")
                chain_text.append(syscall, style="yellow bold" if syscall in SUSPICIOUS_SYSCALLS else "white")

            table.add_row(
                Text(t.timestamp, style="dim red"),
                Text(str(t.pid), style="bold red"),
                Text(t.comm[:12], style="bold red"),
                Text(f"{t.score:.2f}", style="bold bright_red"),
                Text(t.reason, style="bright_red"),
                chain_text,
            )

        if not visible:
            return Panel(Align.center(Text("  ✓ No threats detected", style="dim green"), vertical="middle"), title="[bold red]🛡  THREAT LOG[/bold red]", border_style="red", box=box.ROUNDED, padding=(0, 0))

        return Panel(table, title="[bold red]🛡  THREAT LOG[/bold red]", border_style="red", box=box.ROUNDED, padding=(0, 0))

class SystemStatusPanel:
    @staticmethod
    def render(start_time: datetime, total_events: int) -> Panel:
        uptime = datetime.now() - start_time
        seconds = max(1, int(uptime.total_seconds()))
        eps = total_events // seconds

        table = Table(box=None, expand=True, show_header=False, padding=(0, 1))
        table.add_column("Key", style="bold cyan", width=18)
        table.add_column("Value", style="bright_white")
        
        table.add_row("Uptime:", str(timedelta(seconds=seconds)))
        table.add_row("Total Events:", f"{total_events:,}")
        table.add_row("Events/Sec (EPS):", f"{eps:,} evt/s")
        table.add_row("Whitelist:", ", ".join(sorted(PROTECTED_COMMS)[:6]) + ("..." if len(PROTECTED_COMMS) > 6 else ""))
        table.add_row("Engine Status:", "[bold green]ONLINE[/bold green] (ML + Heuristics)")
        table.add_row("In-Kernel Killer:", "[bold green]ARMED[/bold green] (BPF_MAP)")

        return Panel(table, title="[bold bright_blue]⚙️  SYSTEM STATUS & ML ENGINE[/bold bright_blue]", border_style="bright_blue", box=box.ROUNDED, padding=(1, 1))

class StatsFooterPanel:
    @staticmethod
    def render(start_time: datetime, monitored: int, anomalies: int, killed: int) -> Panel:
        uptime = datetime.now() - start_time
        uptime_str = str(timedelta(seconds=int(uptime.total_seconds())))

        stats = Text()
        stats.append("  📊 ", style="bold cyan")
        stats.append("MONITORED: ", style="dim white")
        stats.append(f"{monitored:,}", style="bold bright_green")
        stats.append("   │   ", style="dim")
        stats.append("⚠  ANOMALIES: ", style="dim white")
        stats.append(f"{anomalies:,}", style="bold yellow")
        stats.append("   │   ", style="dim")
        stats.append("💀 KILLED: ", style="dim white")
        stats.append(f"{killed:,}", style="bold red")
        stats.append("   │   ", style="dim")
        stats.append("⏱  UPTIME: ", style="dim white")
        stats.append(uptime_str, style="bold bright_cyan")
        stats.append("   │   ", style="dim")
        stats.append("🕐 ", style="dim")
        stats.append(datetime.now().strftime("%H:%M:%S"), style="dim white")

        return Panel(Align.center(stats), style="dim", box=box.SQUARE, padding=(0, 0))


# ── Dashboard Orchestrator ───────────────────────────────────────────────────

class ShieldDashboard:
    """
    Rich-based live terminal dashboard for eBPF-Shield.
    """

    MAX_FEED = 100
    MAX_THREATS = 50
    DISPLAY_FEED = 15
    DISPLAY_THREATS = 6

    def __init__(self, mode: str = "DETECTING") -> None:
        self.mode: str = mode.upper()
        self.console: Console = Console()
        self._live: Optional[Live] = None
        self._start_time: datetime = datetime.now()

        # Data stores
        self._syscall_feed: deque[SyscallEvent] = deque(maxlen=self.MAX_FEED)
        self._processes: dict[int, ProcessEntry] = {}
        self._threats: deque[ThreatEntry] = deque(maxlen=self.MAX_THREATS)

        # Stats
        self._monitored: int = 0
        self._anomalies: int = 0
        self._killed: int = 0
        self._total_events: int = 0  # Tracked for EPS
        
        self._proc_lock: threading.Lock = threading.Lock()
        self._dirty: bool = False
        self._layout: Optional[Layout] = None

    def update_syscall_feed(self, event_dict: dict) -> None:
        self._total_events += 1
        self._syscall_feed.append(SyscallEvent(
            timestamp=event_dict.get("timestamp", datetime.now().strftime("%H:%M:%S.%f")[:-3]),
            pid=int(event_dict.get("pid", 0)),
            comm=str(event_dict.get("comm", "?")),
            syscall_name=str(event_dict.get("syscall_name", "?")),
            arg=str(event_dict.get("arg", "")),
        ))
        self._dirty = True

    def update_process_table(self, pid: int, comm: str, score: float, status: str) -> None:
        with self._proc_lock:
            self._processes[pid] = ProcessEntry(
                pid=pid, comm=comm, score=score, status=status,
                last_seen=datetime.now().strftime("%H:%M:%S"),
            )
        self._dirty = True

    def add_threat(self, pid: int, comm: str, score: float, reason: str, chain: list[str] | None = None) -> None:
        self._threats.append(ThreatEntry(
            timestamp=datetime.now().strftime("%H:%M:%S"),
            pid=pid, comm=comm, score=score, reason=reason, chain=chain or [],
        ))

    def update_stats(self, monitored: int, anomalies: int, killed: int) -> None:
        self._monitored = monitored
        self._anomalies = anomalies
        self._killed = killed
        self._dirty = True

    def _build_layout(self) -> Layout:
        """Assemble the 5-panel layout (cached, built once)."""
        if self._layout is not None:
            return self._layout

        layout = Layout()

        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body", ratio=3),
            Layout(name="bottom_tier", size=self.DISPLAY_THREATS + 4),
            Layout(name="footer", size=3),
        )

        layout["body"].split_row(
            Layout(name="feed", ratio=1),
            Layout(name="procs", ratio=1),
        )

        layout["bottom_tier"].split_row(
            Layout(name="threat", ratio=2),
            Layout(name="status", ratio=1),
        )

        self._layout = layout
        return layout

    def _render(self) -> Layout:
        layout = self._build_layout()
        layout["header"].update(HeaderPanel.render(self.mode))
        layout["feed"].update(SyscallFeedPanel.render(self._syscall_feed, self.DISPLAY_FEED))
        layout["procs"].update(ProcessMonitorPanel.render(self._processes, self._proc_lock, self.DISPLAY_FEED))
        layout["threat"].update(ThreatLogPanel.render(self._threats, self.DISPLAY_THREATS))
        layout["status"].update(SystemStatusPanel.render(self._start_time, self._total_events))
        layout["footer"].update(StatsFooterPanel.render(self._start_time, self._monitored, self._anomalies, self._killed))
        self._dirty = False
        return layout

    def start(self) -> Live:
        self._start_time = datetime.now()
        self._layout = None  # Reset cached layout
        
        # Check if we have a TTY for the dashboard
        if not sys.stdout.isatty():
            print("\033[33m[!] Warning: No TTY detected. Dashboard might not render correctly.\033[0m")
            # Create a dummy Live object that doesn't clear the screen
            self._live = Live(
                self._render(),
                console=self.console,
                refresh_per_second=1,
                screen=False,
            )
        else:
            self.console.clear()
            self._live = Live(
                self._render(),
                console=self.console,
                refresh_per_second=4,
                screen=True,
            )
            
        try:
            self._live.start()
        except Exception as e:
            print(f"\033[31m[!] Failed to start dashboard: {e}\033[0m")
            # Create a mock Live object so the caller doesn't crash
            class MockLive:
                def update(self, *args, **kwargs): pass
                def stop(self): pass
            self._live = MockLive()
            
        return self._live

    def stop(self) -> None:
        if self._live is not None:
            self._live.stop()
            self._live = None


# ── Standalone demo / test harness ───────────────────────────────────────────

if __name__ == "__main__":
    import random
    import signal

    DEMO_COMMS = ["sshd", "nginx", "python3", "bash", "curl", "node", "postgres", "systemd"]
    DEMO_SYSCALLS = ["read", "write", "openat", "close", "mmap", "clone", "execve", "connect"]
    SUSPICIOUS = ["ptrace", "setuid", "mount"]
    DEMO_ARGS = ["/etc/passwd", "/tmp/data", "0.0.0.0:4444", "/dev/null", ""]

    ATTACK_COMMS = ["exploit.py", "rev_shell"]
    ATTACK_CHAINS = [
        ["openat", "read", "connect", "write"],
        ["ptrace", "mmap", "execve"],
    ]

    dashboard = ShieldDashboard(mode="DRY-RUN (TESTING)")
    signal.signal(signal.SIGINT, lambda s, f: [dashboard.stop(), sys.exit(0)])
    live = dashboard.start()

    try:
        tick = 0
        while True:
            # Syscalls
            for _ in range(random.randint(5, 15)):
                is_susp = random.random() < 0.05
                dashboard.update_syscall_feed({
                    "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
                    "pid": random.randint(1000, 65000),
                    "comm": random.choice(DEMO_COMMS),
                    "syscall_name": random.choice(SUSPICIOUS if is_susp else DEMO_SYSCALLS),
                    "arg": random.choice(DEMO_ARGS),
                })

            # Processes
            for _ in range(random.randint(1, 4)):
                pid = random.choice([1001, 1234, 2345, 9999])
                score = max(0.0, min(1.0, random.gauss(0.2, 0.18)))
                status = "safe" if score < 0.65 else ("warning" if score < 0.85 else "threat")
                dashboard.update_process_table(pid, random.choice(DEMO_COMMS), round(score, 3), status)

            # Threats
            if tick % 40 == 20:
                dashboard.add_threat(55555, random.choice(ATTACK_COMMS), 0.95, "Privilege escalation", random.choice(ATTACK_CHAINS))
                dashboard.update_process_table(55555, "exploit.py", 0.95, "killed")
                dashboard._killed += 1
                dashboard._anomalies += 1

            dashboard._monitored += random.randint(3, 8)
            dashboard.update_stats(dashboard._monitored, dashboard._anomalies, dashboard._killed)

            live.update(dashboard._render())
            time.sleep(0.25)
            tick += 1
    except KeyboardInterrupt:
        pass
    finally:
        dashboard.stop()
