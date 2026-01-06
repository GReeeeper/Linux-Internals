# Kernel Sentinel // eBPF Process Monitor & Rootkit Detector

![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-red)
![Language](https://img.shields.io/badge/c-ebpf-blue)
![Language](https://img.shields.io/badge/python-gui-yellow)
![Tech](https://img.shields.io/badge/linux-kernel-purple)

**Kernel Sentinel** is an advanced Linux security tool that leverages **eBPF (Extended Berkeley Packet Filter)** to hook low-level syscalls directly in the kernel. It provides real-time detection of rootkits, unauthorized process execution, and sensitive file access with zero overhead.

> **Disclaimer**: Requires Root privileges. 

---

## 🚀 Features

### 1. Kernel-Level Visibility (C/eBPF)
*   **Syscall Monitor**: Intercepts `execve` (Process Execution) and `openat` (File Access).
*   **Network Hooks**: Intercepts `tcp_connect` (Outbound) and `inet_csk_accept` (Inbound) to track every TCP connection.
*   **Stealth Detection**: Detects malicious patterns *before* they return to user space.

### 2. Detection & Active Defense
*   **Malicious Binaries**: Flags execution of recon tools (`nmap`, `ncat`, `insmod`).
*   **Intrusion Response**: 
    *   **Inbound**: Detects external connections.
    *   **Popup Alert**: Prompts user to **[ BLOCK IP ]** or **[ ALLOW ]**.
    *   **Firewalling**: Automatically runs `iptables` to drop traffic from banned IPs.

### 3. Sentinel Dashboard (Python)
*   **Visual Alerts**: A "Red Alert" popup system for critical intrusions.
*   **Live Log**: Real-time streaming of kernel events from `/sys/kernel/tracing/trace_pipe`.
*   **Cyberpunk UX**: Dark-mode GUI for the modern security researcher.

---

## 🛠️ Architecture

```mermaid
graph TD
    A["User Space App"] -->|"Syscall (execve)"| B("Kernel")
    B -->|"eBPF Hook (kprobe)"| C("Kernel Sentinel (BPF)")
    C -->|"Malicious?"| D{Analysis}
    D -->|"Yes"| E("Alert -> Trace Pipe")
    E -->|"Read"| F("Python Dashboard")
    D -->|"No"| G("Allow Execution")
```

---

## 📦 Installation & Usage

### Prerequisites
*   **Linux Kernel 5.8+** (with BTF support)
*   **Clang/LLVM** (for compiling BPF)
*   **Python 3** (Tkinter)

### 1. Compile the eBPF Probe
Compile the C code into a BPF Object file.
```bash
clang -O2 -g -target bpf -c exec_monitor.bpf.c -o exec_monitor.o
```

### 2. Launch the Sentinel
Run the Python GUI as root to load the probe and start monitoring.
```bash
sudo python monitor_gui.py
```

### 3. Trigger an Alert (Test)
Open a new terminal and try a suspicious command:
```bash
/usr/bin/whoami
# or
cat /etc/shadow
```
**Result**: The dashboard will flash RED with an "INTRUSION DETECTED" warning.

---

## 📸 Screenshots
<img width="703" height="515" alt="image" src="https://github.com/user-attachments/assets/63362139-e4de-4a9a-9104-adcd194c9835" />



---

## ⚠️ Legal & Ethics
This tool interacts with the Linux Kernel. Improper modification of BPF code can cause system instability (Kernel Panics). Use in a controlled environment.
