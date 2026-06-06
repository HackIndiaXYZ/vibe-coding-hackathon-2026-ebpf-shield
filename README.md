# vibe-coding-hackathon-2026-ebpf-shield
Hackathon team repository for eBPF-Shield - [hackindia-team:vibe-coding-hackathon-2026:ebpf-shield]

# 🛡️ eBPF-Shield

**eBPF-Shield** is a real-time, AI-driven Linux kernel security monitor. It uses eBPF (Extended Berkeley Packet Filter) to trace system calls at the kernel level, aggregates behavioral telemetry in user-space, and uses a combination of Machine Learning and deterministic heuristics to instantaneously neutralize zero-day threats, privilege escalations, and data exfiltration.

![Status](https://img.shields.io/badge/Status-Production%20MVP-success)
![Platform](https://img.shields.io/badge/Platform-Linux%20(Kernel%205.3%2B)-blue)

## ✨ Key Features

1. **Kernel-Level Telemetry**: Deploys eBPF tracepoints directly into the Linux kernel to intercept critical syscalls (`execve`, `openat`, `connect`, `setuid`, etc.) with near-zero overhead.
2. **AI Anomaly Detection**: Uses a sliding-window feature extractor to feed live behavioral telemetry into a pre-trained **Isolation Forest** machine learning model to detect anomalous execution patterns.
3. **Deterministic Heuristics**: Catches specific attack chains (e.g., privilege escalation sequences, automated sensitive file harvesting, reverse shells).
4. **Instant In-Kernel Kill Switch**: Resolves the classic user-space TOCTOU (Time-Of-Check to Time-Of-Use) race condition. When a threat is detected, the Python engine updates a shared eBPF Map, empowering the kernel to instantly annihilate the malicious process (`SIGKILL`) on its next syscall—before user-space even reacts.
5. **TUI Dashboard**: A stunning, terminal-based Rich dashboard showing live syscall feeds, process scores, and a forensic Threat Log.

---

## ⚙️ Prerequisites

To run eBPF-Shield, you must be on a Linux environment (or WSL2) with eBPF support.
- **Kernel**: Linux 5.3+ (requires BPF, kprobes, and tracepoints)
- **Privileges**: `root` (required to load eBPF programs)
- **Dependencies**: 
  - `bcc` (BPF Compiler Collection)
  - Python 3.8+

### Installing BCC (Fedora / RHEL / CentOS)
```bash
sudo dnf install bcc bcc-tools python3-bcc
```

### Installing Python Dependencies
```bash
pip3 install scikit-learn numpy psutil rich
```

---

## 🚀 Usage

eBPF-Shield operates in two primary modes: **Training** and **Detection**.

### 1. Training the AI Model
Before detecting anomalies, you must train the Isolation Forest model on benign workload behavior.
```bash
# Start training mode (collects data for 60 seconds)
sudo python3 main.py train --duration 60

# In another terminal, run benign workloads so the model learns normal behavior:
bash demo/benign_workload.sh
```

### 2. Live Detection & Enforcement
Once trained, launch the shield in detection mode. It will actively kill any processes it deems malicious.
```bash
sudo python3 main.py detect
```

### 3. Dry-Run Mode
If you want to observe threats on the dashboard *without* killing the processes (useful for auditing and testing):
```bash
sudo python3 main.py detect --dry-run
```

---

## ⚔️ Testing the Defenses (Demo Scripts)

The project includes several demo scripts to simulate real-world attacks. Run the shield in a primary terminal, and execute these scripts in a secondary terminal to watch the kernel strike them down.

### 1. Privilege Escalation & Lateral Movement
Simulates reading `/etc/shadow`, attempting `setuid(0)`, and spawning a root shell.
```bash
sudo bash demo/attack_privesc.sh
```
*Expected Result:* Instantly caught by the `priv_esc_sequence` heuristic. The spawned shell is forcefully killed.

### 2. Data Exfiltration
Simulates an automated script rapidly harvesting `/etc/passwd`, `/etc/hosts`, and SSH keys, followed by an attempted `netcat` exfiltration.
```bash
bash demo/attack_file_exfil.sh
```
*Expected Result:* Caught by the `sensitive_file_access` heuristic. The automated `cat` processes are annihilated by the kernel blacklist.

### 3. Reverse Shell
Simulates a classic Python reverse shell binding to a socket, duplicating file descriptors, and spawning `/bin/sh` via `execve`.
```bash
python3 demo/attack_reverse_shell.py
```
*Expected Result:* The spawned shell is intercepted and killed by the in-kernel eBPF kill switch.

### 4. Process Injection
Simulates an attacker attempting to hijack another running process using the `ptrace` syscall.
```bash
python3 demo/attack_process_injection.py
```
*Expected Result:* Caught by the `ptrace` heuristic. The fallback eBPF `kprobe` guarantees interception even on systems that drop tracepoints.

### 5. Fileless Malware Execution
Simulates writing an executable payload directly into an anonymous memory file (`memfd_create`) and executing it from RAM, bypassing disk-based antivirus scanners.
```bash
python3 demo/attack_fileless_memfd.py
```
*Expected Result:* Caught by the `fileless_malware_execution` heuristic. eBPF intercepts the execution and instantly neutralizes the threat.

---

## 🏗️ Architecture

1. **`ebpf/probes.py`**: The C-based eBPF program injected into the kernel. It pushes syscall events to a high-speed `perf_buffer` and checks the `blacklist` eBPF Map on every syscall.
2. **`core/consumer.py`**: Reads the `perf_buffer` and aggregates raw events into 2-second sliding windows per PID.
3. **`core/feature_extractor.py`**: Condenses raw syscalls into a 15-dimensional mathematical feature vector (e.g., syscall rates, unique syscalls, entropy).
4. **`core/detector.py`**: The brain. Evaluates the feature vector against the `scikit-learn` Isolation Forest and deterministic rules.
5. **`core/killer.py`**: The enforcer. Writes malicious PIDs to the kernel `blacklist` map for instant-blocking, executes a user-space fallback `SIGKILL`, and writes a JSON record to `data/forensic_log.jsonl`.
6. **`dashboard/tui.py`**: The `rich`-based terminal UI.
