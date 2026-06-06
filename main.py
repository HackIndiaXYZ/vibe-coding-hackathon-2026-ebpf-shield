#!/usr/bin/env python3
"""
main.py — CLI entry point for eBPF-Shield.

Provides two subcommands:
    train   — Collect syscall events and train the anomaly detection model
    detect  — Load a trained model and monitor in real-time, killing threats

Usage:
    sudo python3 main.py train --duration 300
    sudo python3 main.py detect
    sudo python3 main.py detect --dry-run

Requires:
    - Linux kernel 5.15+ with eBPF support
    - BCC (BPF Compiler Collection) Python bindings
    - Root privileges (for eBPF probe attachment)
"""

from __future__ import annotations

import argparse
import os
import signal
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional
import logging

# Redirect all root logging to a file to prevent corrupting the TUI
logging.basicConfig(
    filename="data/shield.log",
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)


# ── Graceful BCC import handling ─────────────────────────────────────────────

def _check_bcc_available() -> bool:
    """Check if BCC Python bindings are available."""
    try:
        from bcc import BPF  # noqa: F401
        return True
    except ImportError:
        return False


def _print_bcc_install_help() -> None:
    """Print helpful installation instructions for BCC."""
    print("\033[1;31m╔══════════════════════════════════════════════════════╗\033[0m")
    print("\033[1;31m║  ERROR: BCC (BPF Compiler Collection) not found!    ║\033[0m")
    print("\033[1;31m╚══════════════════════════════════════════════════════╝\033[0m")
    print()
    print("\033[1meBPF-Shield requires BCC Python bindings for kernel-level\033[0m")
    print("\033[1msyscall monitoring. Install BCC for your distribution:\033[0m")
    print()
    print("\033[36m  Fedora / RHEL:\033[0m")
    print("    sudo dnf install python3-bcc bcc-tools bcc-devel")
    print()
    print("\033[36m  Ubuntu / Debian:\033[0m")
    print("    sudo apt install python3-bpfcc bpfcc-tools libbpfcc-dev")
    print()
    print("\033[36m  Arch Linux:\033[0m")
    print("    sudo pacman -S bcc bcc-tools python-bcc")
    print()
    print("\033[36m  From source:\033[0m")
    print("    https://github.com/iovisor/bcc/blob/master/INSTALL.md")
    print()
    print("\033[33mAlso ensure:\033[0m")
    print("  • Linux kernel 5.15+ with CONFIG_BPF=y")
    print("  • Running as root (sudo)")
    print("  • Python 3.10+")
    print()


# ── Project paths ────────────────────────────────────────────────────────────

PROJECT_ROOT = Path(__file__).resolve().parent
DATA_DIR = PROJECT_ROOT / "data"
MODEL_PATH = DATA_DIR / "baseline_model.pkl"
TRAINING_DATA_PATH = DATA_DIR / "training_events.json"


def _ensure_data_dir() -> None:
    """Ensure the data/ directory exists."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)


# ── Signal handling ──────────────────────────────────────────────────────────

_shutdown_requested = False


def _signal_handler(signum: int, frame) -> None:
    """Handle SIGINT/SIGTERM for clean shutdown."""
    global _shutdown_requested
    _shutdown_requested = True
    print("\n\033[33m[!] Shutdown signal received. Cleaning up...\033[0m")


# ── Training mode ────────────────────────────────────────────────────────────

def run_training(duration: int) -> int:
    """Run eBPF-Shield in training mode.

    Collects syscall events for the specified duration, extracts features,
    trains the anomaly detection model, and saves it to disk.

    Args:
        duration: Training duration in seconds.

    Returns:
        Exit code (0 = success, 1 = error).
    """
    global _shutdown_requested

    if not _check_bcc_available():
        _print_bcc_install_help()
        return 1

    # Lazy imports (only after BCC check passes)
    from ebpf.probes import SyscallProbe
    from core.feature_extractor import FeatureExtractor
    from core.detector import AnomalyDetector

    _ensure_data_dir()

    print("\033[1;36m╔══════════════════════════════════════════════════════╗\033[0m")
    print("\033[1;36m║  eBPF-Shield — Training Mode                        ║\033[0m")
    print(f"\033[1;36m║  Duration: {duration}s                                      ║\033[0m")
    print("\033[1;36m╚══════════════════════════════════════════════════════╝\033[0m")
    print()

    # Initialize components
    print("[*] Initializing eBPF syscall probe...")
    extractor = FeatureExtractor()
    detector = AnomalyDetector()

    # For training, we collect ALL raw events (bypass sliding window pruning)
    all_raw_events = []
    import threading
    events_lock = threading.Lock()

    def _training_callback(event):
        with events_lock:
            all_raw_events.append(event)

    probe = SyscallProbe(callback=_training_callback, exclude_pids={os.getpid()})

    # Start collecting
    print(f"[*] Collecting syscall events for {duration} seconds...")
    print("[*] Press Ctrl+C to stop early.")
    print("[*] TIP: Generate activity! Run 'bash demo/benign_workload.sh' in another terminal.\n")

    probe_thread = threading.Thread(target=probe.start, daemon=True)
    probe_thread.start()
    
    start_time = time.time()

    try:
        while not _shutdown_requested:
            elapsed = time.time() - start_time
            if elapsed >= duration:
                break

            # Progress update every 5 seconds
            if int(elapsed) % 5 == 0 and int(elapsed) > 0:
                remaining = int(duration - elapsed)
                with events_lock:
                    count = len(all_raw_events)
                print(f"  [{int(elapsed):>4}s] Events collected: {count:,}  "
                      f"| Remaining: {remaining}s")

            time.sleep(1)

    except KeyboardInterrupt:
        print("\n[!] Training interrupted by user.")

    finally:
        probe.stop()

    with events_lock:
        total_events = len(all_raw_events)

    print(f"\n[*] Collection complete. Total events: {total_events:,}")

    if total_events < 5:
        print("\033[31m[!] Too few events. Run 'bash demo/benign_workload.sh' during training.\033[0m")
        return 1

    # Extract features — group by PID, then slice into 2-second windows
    print("[*] Extracting features from collected events...")
    
    # Group events by PID
    from collections import defaultdict
    pid_events = defaultdict(list)
    for event in all_raw_events:
        pid_events[event.pid].append(event)

    print(f"    Unique processes observed: {len(pid_events)}")

    # For each PID, create overlapping time windows and extract features
    WINDOW_NS = 2_000_000_000  # 2 seconds in nanoseconds
    STEP_NS = 1_000_000_000    # 1 second step (50% overlap)
    MIN_EVENTS = 2

    features = []
    for pid, events in pid_events.items():
        events.sort(key=lambda e: e.timestamp_ns)
        
        if len(events) < MIN_EVENTS:
            continue

        # Sliding window over the process's events
        t_start = events[0].timestamp_ns
        t_end = events[-1].timestamp_ns

        window_start = t_start
        while window_start <= t_end:
            window_end = window_start + WINDOW_NS
            window_events = [e for e in events if window_start <= e.timestamp_ns < window_end]
            
            if len(window_events) >= MIN_EVENTS:
                fv = extractor.extract(window_events)
                features.append(fv)

            window_start += STEP_NS

        # Also extract features from the full process lifetime
        if len(events) >= MIN_EVENTS:
            fv = extractor.extract(events)
            features.append(fv)

    print(f"    Feature vectors generated: {len(features)}")

    if len(features) == 0:
        print("\033[31m[!] No features extracted. Not enough data to train.\033[0m")
        return 1

    # Train the model
    print("[*] Training anomaly detection model (Isolation Forest)...")
    detector.train(features)
    print("    Model training complete.")
    print("\033[32m[✓] Model saved successfully!\033[0m")

    print()
    print("\033[1;32m╔══════════════════════════════════════════════════════╗\033[0m")
    print("\033[1;32m║  ✅ Training complete!                               ║\033[0m")
    print(f"\033[1;32m║  Events: {total_events:<10,} Features: {len(features):<10}       ║\033[0m")
    print(f"\033[1;32m║  Model:  data/baseline_model.pkl                    ║\033[0m")
    print("\033[1;32m╚══════════════════════════════════════════════════════╝\033[0m")

    return 0


# ── Detection mode ───────────────────────────────────────────────────────────

def run_detection(dry_run: bool = False) -> int:
    """Run eBPF-Shield in detection/enforcement mode.

    Loads the trained model, attaches eBPF probes, and monitors syscalls
    in real-time. Anomalous processes are killed (unless --dry-run).

    Args:
        dry_run: If True, detect but don't kill processes.

    Returns:
        Exit code (0 = success, 1 = error).
    """
    global _shutdown_requested

    if not _check_bcc_available():
        _print_bcc_install_help()
        return 1

    # Lazy imports
    from ebpf.probes import SyscallProbe
    from core.consumer import EventConsumer
    from core.feature_extractor import FeatureExtractor
    from core.detector import AnomalyDetector
    from core.killer import ProcessKiller
    from dashboard.tui import ShieldDashboard
    from ebpf.syscall_map import syscall_name as _syscall_name

    _ensure_data_dir()

    # Check for trained model
    if not MODEL_PATH.exists():
        print("\033[31m[!] No trained model found at:\033[0m", MODEL_PATH)
        print("    Run training first:  sudo python3 main.py train")
        return 1

    mode = "DRY-RUN" if dry_run else "DETECTING"
    print(f"\033[1;36m[*] eBPF-Shield — {mode} mode\033[0m")

    # Initialize components
    print("[*] Loading anomaly detection model...")
    detector = AnomalyDetector()
    detector.load()
    print("    Model loaded successfully.")

    import threading
    consumer = EventConsumer()
    
    # Store events to be processed in the main thread
    pending_windows = []
    def _detect_ingest(event):
        window = consumer.ingest(event)
        if window:
            pending_windows.append((event.pid, window))

    # Build comprehensive exclusion set: self + entire process tree
    _exclude = {os.getpid()}
    try:
        import psutil as _psutil
        _me = _psutil.Process(os.getpid())
        # Exclude parents/ancestors
        _parent = _me.parent()
        while _parent is not None:
            _exclude.add(_parent.pid)
            _parent = _parent.parent()
        # Exclude children (recursive)
        for _child in _me.children(recursive=True):
            _exclude.add(_child.pid)
    except Exception as e:
        import traceback
        with open("data/crash.log", "w") as f:
            traceback.print_exc(file=f)
        import logging
        logging.getLogger("ebpf-shield").error("Fatal error: %s", e)
        sys.exit(1)

    probe = SyscallProbe(callback=_detect_ingest, exclude_pids=_exclude)
    extractor = FeatureExtractor()
    
    # Ensure killer also knows about the entire process tree and the global PID
    killer = ProcessKiller(dry_run=dry_run, blacklist_map=probe.blacklist_map)
    for p in _exclude:
        killer._protected_pids.add(p)
    if hasattr(probe, "global_pid"):
        killer._protected_pids.add(probe.global_pid)
        
    dashboard = ShieldDashboard(mode=mode)

    print("[*] Starting eBPF probe and dashboard...")
    probe_thread = threading.Thread(target=probe.start, daemon=True)
    probe_thread.start()
    
    live = dashboard.start()

    monitored = 0
    anomalies = 0
    killed = 0

    try:
        from datetime import datetime as _dt
        while not _shutdown_requested:
            from config import PROTECTED_COMMS

            # Process pending windows (cap per tick to keep UI responsive)
            processed_this_tick = 0
            while pending_windows and processed_this_tick < 50:
                pid, events = pending_windows.pop(0)
                processed_this_tick += 1
                
                # Update syscall feed on dashboard (sample to avoid flooding)
                if processed_this_tick <= 10:
                    for event in events[-2:]:
                        ts_str = _dt.now().strftime("%H:%M:%S.%f")[:-3]
                        event_dict = {
                            "timestamp": ts_str,
                            "pid": event.pid,
                            "comm": event.comm,
                            "syscall_name": _syscall_name(event.syscall_id),
                            "arg": event.arg,
                        }
                        dashboard.update_syscall_feed(event_dict)

                features = extractor.extract(events)
                if features is None:
                    continue

                monitored += 1
                is_anomaly, score, reason = detector.predict(features)
                comm = events[-1].comm if events else "unknown"

                # Normalize score for dashboard display (0=safe, 1=threat)
                display_score = max(0.0, min(1.0, 0.5 - score))

                # If the process is globally protected, ignore anomaly detections
                is_protected = comm in PROTECTED_COMMS or pid in killer._protected_pids

                if is_anomaly and not is_protected:
                    anomalies += 1
                    chain = [_syscall_name(e.syscall_id) for e in events[:5]]

                    dashboard.add_threat(
                        pid=pid,
                        comm=comm,
                        score=display_score,
                        reason=reason,
                        chain=chain,
                    )
                    dashboard.update_process_table(pid, comm, display_score, "threat")

                    # Kill unless dry-run
                    if not dry_run:
                        success = killer.kill(pid, reason=reason, score=score, comm=comm)
                        if success:
                            killed += 1
                            dashboard.update_process_table(
                                pid, comm, display_score, "killed"
                            )
                else:
                    status = "warning" if display_score > 0.4 else "safe"
                    dashboard.update_process_table(pid, comm, display_score, status)

            # Update dashboard data — Rich auto-refreshes at 4fps
            dashboard.update_stats(monitored, anomalies, killed)
            if dashboard._dirty and live is not None:
                live.update(dashboard._render())
            time.sleep(0.15)

    except KeyboardInterrupt:
        print("\n[!] Detection stopped by user.")

    finally:
        probe.stop()
        dashboard.stop()

    print()
    print(f"\033[1;36m[*] Session summary:\033[0m")
    print(f"    Processes monitored: {monitored:,}")
    print(f"    Anomalies detected: {anomalies:,}")
    print(f"    Processes killed:   {killed:,}")

    return 0


# ── CLI argument parsing ─────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    """Build the argparse parser with train/detect subcommands."""
    parser = argparse.ArgumentParser(
        prog="ebpf-shield",
        description=(
            "eBPF-Shield — Kernel-level AI security monitor.\n"
            "Uses eBPF probes + Isolation Forest to detect and terminate\n"
            "malicious processes in real-time."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  sudo python3 main.py train --duration 300\n"
            "  sudo python3 main.py detect\n"
            "  sudo python3 main.py detect --dry-run\n"
        ),
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    subparsers.required = True

    # ── train ──
    train_parser = subparsers.add_parser(
        "train",
        help="Collect syscall events and train the anomaly model",
        description="Run eBPF-Shield in training mode to build a baseline.",
    )
    train_parser.add_argument(
        "--duration", "-d",
        type=int,
        default=300,
        metavar="SECONDS",
        help="Training duration in seconds (default: 300)",
    )

    # ── detect ──
    detect_parser = subparsers.add_parser(
        "detect",
        help="Monitor and detect/kill anomalous processes",
        description="Run eBPF-Shield in detection mode with live dashboard.",
    )
    detect_parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Detect anomalies but don't kill processes",
    )

    return parser


# ── Entry point ──────────────────────────────────────────────────────────────

def main() -> int:
    """Main entry point for eBPF-Shield."""
    # Register signal handlers
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    # Check root
    if os.geteuid() != 0:
        print("\033[33m[!] Warning: eBPF-Shield typically requires root privileges.\033[0m")
        print("    Run with: sudo python3 main.py <command>")
        print()

    parser = build_parser()
    args = parser.parse_args()

    if args.command == "train":
        return run_training(duration=args.duration)
    elif args.command == "detect":
        return run_detection(dry_run=args.dry_run)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
