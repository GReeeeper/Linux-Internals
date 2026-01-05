# eBPF Monitor: Usage Guide

## 1. Compilation
We compile the C code into an eBPF Object file (`.o`).
```bash
clang -O2 -g -target bpf -c exec_monitor.bpf.c -o exec_monitor.o
```

## 2. Load into Kernel
We use `bpftool` to load the program and attach it to the kernel tracepoint.
```bash
# Load and attach (auto-attach via SEC name)
sudo bpftool prog load exec_monitor.o /sys/fs/bpf/exec_monitor autoattach
```

## 3. Monitor Output
The `bpf_printk` output goes to the kernel trace pipe.
```bash
sudo cat /sys/kernel/tracing/trace_pipe
```

## 4. Test
Open a new terminal and run:
```bash
/usr/bin/whoami
```
You should see:
```
   whoami-12345 [000] .... 1234.567890: bpf_trace_printk: [ALERT] Malicious Execution detected: /usr/bin/whoami
```

## 5. Desktop Mode (Optional)
Run the Python GUI for visual alerts:
```bash
sudo python monitor_gui.py
```
-   It will auto-load the BPF object.
-   When `whoami` runs, you get a RED ALERT popup.

