# 🧠 eBPF-Shield: Technical Deep Dive & Learning Guide

Welcome to the internal documentation for **eBPF-Shield**. This document is designed to teach you exactly how the project works under the hood, the technologies it uses, and the computer science concepts that make it possible.

---

## 1. The Technology Stack

eBPF-Shield bridges the gap between low-level Linux kernel programming and high-level Python AI. 

* **eBPF (Extended Berkeley Packet Filter)**: The core technology. It allows us to run sandboxed, highly efficient C code directly inside the Linux kernel without changing kernel source code or loading vulnerable kernel modules.
* **BCC (BPF Compiler Collection)**: A toolkit that makes it easier to write eBPF programs. It compiles our C code on the fly and provides the Python bindings to interact with the kernel.
* **Python 3**: The orchestrator. It manages the user-space logic, machine learning, and the terminal dashboard.
* **Scikit-Learn**: The Python library powering our AI model (`IsolationForest`) used for anomaly detection.
* **Rich**: A Python library used to render the beautiful, live-updating Terminal User Interface (TUI).

---

## 2. Core Concepts You Should Know

To understand this project, you need to grasp three main concepts:

### A. Tracepoints
A **tracepoint** is a pre-defined hook placed into the Linux kernel code by kernel developers. Whenever the kernel does something important (like executing a program, opening a file, or making a network connection), the tracepoint fires. We attach our eBPF C program to these tracepoints.

### B. Sliding Time Windows
Instead of analyzing one system call at a time (which is too noisy), we group a process's behavior into a **2-second sliding window**. If a process opens 5 files and makes 2 network connections in 2 seconds, we analyze that *entire block of behavior* together.

### C. Isolation Forest (Machine Learning)
Unlike traditional antivirus that uses "signatures" (looking for known bad viruses), an Isolation Forest is an **unsupervised learning** algorithm. During training, it learns what "normal" behavior looks like. During detection, if a process behaves in a mathematically bizarre way that the model has never seen before, it is flagged as an anomaly.

---

## 3. Architecture & Data Flow

Here is the exact step-by-step journey of a system call, from the moment a user types a command to the moment it gets killed:

1. **User Action**: A user types `cat /etc/passwd`.
2. **Kernel Hook**: The Linux kernel fires the `sys_enter_openat` tracepoint.
3. **eBPF C Code**: Our C code (`ebpf/probes.py`) intercepts the call, packages the PID and filename into a C-struct, and pushes it to a high-speed ring buffer (`BPF_RINGBUF_OUTPUT`).
4. **Python Consumer**: `core/consumer.py` reads the ring buffer and groups the events by PID into time windows.
5. **Feature Extraction**: `core/feature_extractor.py` converts the raw events into a 15-dimensional mathematical array (e.g., counting the rate of syscalls, checking if the file opened was sensitive).
6. **Detection Brain**: `core/detector.py` runs the array through the AI model and our hardcoded heuristic rules.
7. **The Execution**: If flagged as malicious, `core/killer.py` instantly updates an eBPF Map in the kernel to block the process, and sends a user-space `SIGKILL` to destroy it.

---

## 4. Component Deep Dive

Let's look at the specific files in the codebase and what they do.

### 🛡️ `ebpf/probes.py` (The Kernel Sentinel)
This file contains actual C code wrapped in a Python string. 
* It defines the `TRACEPOINT_PROBE` functions.
* It contains the **Blacklist Map** (`BPF_HASH(blacklist, u32, u32)`). At the start of every tracepoint, it checks if the current PID is in the blacklist. If yes, it calls `bpf_send_signal(9)` to instantly kill it.
* **Shift-Left Heuristic**: It implements unconditional checks in the kernel (e.g., banning `ptrace` for non-root users) to instantly kill malicious activity before it even reaches user-space.

### 📦 `core/consumer.py` (The Data Aggregator)
This is the bridge between the kernel and user-space.
* It uses a polling loop to constantly read the `ring_buffer`.
* It maintains a `sliding_windows` dictionary. Every time a process makes a new syscall, it appends it to that process's window until it has enough data to emit for analysis.

### 🧮 `core/feature_extractor.py` (The Math Engine)
Machine learning models cannot read raw strings or syscall names; they only understand numbers. This file transforms events into 15 numbers (features).
* **Examples of features**: `syscall_count`, `connect_count`, `syscall_rate`, `sensitive_file_access`.
* If it sees a process opening `/etc/shadow`, it increments the `sensitive_file_access` feature counter.

### 🧠 `core/detector.py` (The AI Brain & Rule Engine)
This is the decision-maker. It has two layers of defense:
1. **Heuristics (Rules)**: Hardcoded `if/else` statements. For example, if `sensitive_file > 0`, it instantly flags the process as a threat. This catches known, obvious attacks immediately.
2. **Isolation Forest (AI)**: It feeds the 15 features into the `scikit-learn` model. The model returns an anomaly score. If the score is too low (highly unusual), it flags the process.

### 🔪 `core/killer.py` (The Executioner)
When the detector screams "THREAT!", this class acts.
* **Whitelist Check**: First, it checks `config.py` to see if the process is `systemd`, `sudo`, or `bash`. If it is, it refuses to kill it to prevent crashing the server.
* **In-Kernel Arming**: It pushes the malicious PID into the eBPF Blacklist Map, arming the kernel to instantly terminate the process on its very next syscall.
* **Forensic Logging**: It gathers metadata (like the command line arguments) using `psutil` and writes a permanent JSON log to `data/forensic_log.jsonl`.

### 🖥️ `dashboard/tui.py` (The Visualizer)
This creates the "Hacker Movie" aesthetic.
* It uses the `rich.layout` module to split the terminal into grids.
* It dynamically renders live tables, color-coded threat statuses, and progress bars.

---

## 5. Engineering Challenges Solved

### The TOCTOU Problem (Time-Of-Check to Time-Of-Use)
**The Problem**: User-space Python is relatively slow. A malicious script running `cat /etc/shadow` takes just `0.5 milliseconds` to finish. By the time the event reaches Python and Python says "Kill it!", the `cat` process has already exited.
**Our Solution**: The **eBPF Blacklist Map**. Python calculates the threat, but instead of just trying to kill the process from user-space, it updates a shared memory map. The kernel reads this map synchronously at ring-0. The instant that process tries to make another system call, the kernel instantly executes it from the inside out.

### Process Forking & PID Tracking
**The Problem**: Malware often spawns new child processes to hide.
**Our Solution**: Our eBPF tracepoints capture the `ppid` (Parent PID) alongside the `pid`. While the MVP evaluates threats per-PID, the data structures are designed so that future updates can aggregate child behavior into the parent's anomaly score.

### The Shell Ancestry Whitelist Bypass
**The Problem**: When running a script (like `python3 malicious.py`), the parent shell (`bash`) forks a child process. For a fraction of a millisecond, before the `execve` syscall completes, the child is still named `"bash"`. Because the engine evaluated the *oldest* event in the 2-second window, it saw `"bash"` (a protected system process) and mistakenly granted the malware immunity!
**Our Solution**: The engine was refactored to evaluate the `comm` of the *most recent* event in the window (`events[-1].comm`), ensuring it evaluates the attacker's true process name.

### WSL2 Kernel Tracepoint Evasion
**The Problem**: The `ptrace` attack bypassed detection on Windows Subsystem for Linux (WSL2) because the Microsoft custom kernel sometimes drops the standard `sys_enter_ptrace` tracepoint.
**Our Solution**: We injected a direct `kprobe` (`kprobe____x64_sys_ptrace`) into the eBPF C program. Even if the tracepoint macro fails, the kprobe hooks directly into the raw kernel memory address of the syscall function, making evasion mathematically impossible.

---

## 6. Supported Attack Scenarios

The `demo/` folder contains sophisticated attack simulations designed to prove the efficacy of the ML and heuristic engines:

1. **Process Injection (`attack_process_injection.py`)**: Attempts a stealthy `PTRACE_ATTACH` to hijack a running process.
2. **Fileless Malware (`attack_fileless_memfd.py`)**: Uses `memfd_create` and `execve` to execute a payload strictly from RAM, bypassing disk-based AV scanners.
3. **Data Exfiltration (`attack_file_exfil.sh`)**: Simulates an automated script rapidly harvesting `/etc/passwd` and attempting a `netcat` exfiltration.
4. **Privilege Escalation (`attack_privesc.sh`)**: Simulates a sequence of `/etc/shadow` reads followed by an attempted `setuid(0)` call.
5. **Reverse Shell (`attack_reverse_shell.py`)**: Simulates a classic Python reverse shell binding to a socket, duplicating file descriptors, and spawning `/bin/sh` via `execve`.
