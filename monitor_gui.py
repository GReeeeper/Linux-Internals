import tkinter as tk
from tkinter import messagebox, scrolledtext
import subprocess
import threading
import sys
import os
import time

# Configuration
BPF_OBJECT = "exec_monitor.o"
BPF_PATH = "/sys/fs/bpf/exec_monitor"
TRACE_PIPE = "/sys/kernel/tracing/trace_pipe"

class SentinelApp:
    def __init__(self, root):
        self.root = root
        self.root.title("KERNEL SENTINEL // eBPF MONITOR")
        self.root.geometry("700x500")
        self.root.configure(bg="#050505")

        # 1. Enforce Root Immediately
        self.check_root()

        # Header
        self.header = tk.Label(root, text="::: KERNEL SENTINEL ACTIVE :::", 
                               font=("Consolas", 16, "bold"), fg="#00ff00", bg="#050505")
        self.header.pack(pady=20)

        # Log Area
        frame_log = tk.Frame(root, bg="#111", padx=5, pady=5)
        frame_log.pack(fill=tk.BOTH, expand=True, padx=20)
        
        self.log_area = scrolledtext.ScrolledText(frame_log, width=80, height=20, 
                                                  bg="#000000", fg="#00cc00", font=("Consolas", 10),
                                                  insertbackground="#00ff00", borderwidth=0)
        self.log_area.pack(fill=tk.BOTH, expand=True)
        self.log_area.insert(tk.END, "[*] SYSTEM INITIALIZING... PROBE LOADING...\n")

        # Unload Button
        self.btn_quit = tk.Button(root, text="[ DEACTIVATE PROBE ]", command=self.shutdown, 
                                  bg="#440000", fg="#ffaaaa", font=("Consolas", 11, "bold"), relief=tk.FLAT)
        self.btn_quit.pack(pady=20, iPadx=10)

        # State
        self.running = True
        
        # Schedule startup tasks
        self.root.after(500, self.start_sentinel)

    def check_root(self):
        if os.geteuid() != 0:
            messagebox.showerror("Error", "Must run as ROOT (sudo) to access eBPF!")
            sys.exit(1)

    def start_sentinel(self):
        self.load_bpf()
        self.monitor_thread = threading.Thread(target=self.monitor_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()

    def log(self, message):
        self.log_area.insert(tk.END, f"{time.strftime('%H:%M:%S')} > {message}\n")
        self.log_area.see(tk.END)

    def load_bpf(self):
        self.log("[*] Cleaning up old probes...")
        subprocess.run(["rm", "-f", BPF_PATH])
        
        self.log("[*] Loading eBPF Object...")
        cmd = ["bpftool", "prog", "load", BPF_OBJECT, BPF_PATH, "autoattach"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            self.log(f"[!] Load Failed: {result.stderr}")
            messagebox.showerror("Load Error", f"Failed to load BPF: {result.stderr}")
        else:
            self.log("[+] eBPF PROBE ATTACHED SUCCESSFULLY")
            self.log("[+] Intercepting syscalls: execve, execveat")

    def show_alert(self, message):
        # Flash Main Window
        self.root.configure(bg="#aa0000")
        self.header.configure(bg="#aa0000", fg="white", text="!!! INTRUSION DETECTED !!!")
        self.root.after(500, self.reset_alert)
        
        # Popup
        alert = tk.Toplevel(self.root)
        alert.title("SECURITY ALERT")
        alert.geometry("500x250")
        alert.configure(bg="#220000")
        
        lbl = tk.Label(alert, text="!!! MALICIOUS ACTIVITY !!!", 
                       font=("Impact", 24), fg="red", bg="#220000")
        lbl.pack(pady=20)
        
        msg = tk.Label(alert, text=message.replace("[ALERT] ", ""), font=("Consolas", 12), fg="white", bg="#220000")
        msg.pack(pady=10)
        
        btn = tk.Button(alert, text="ACKNOWLEDGE", command=alert.destroy, bg="red", fg="white", font=("Consolas", 12))
        btn.pack(pady=20)

    def reset_alert(self):
        self.root.configure(bg="#050505")
        self.header.configure(bg="#050505", fg="#00ff00", text="::: KERNEL SENTINEL ACTIVE :::")

    def monitor_loop(self):
        self.log("[*] Monitoring Trace Pipe...")
        try:
            with open(TRACE_PIPE, "r") as f:
                while self.running:
                    line = f.readline()
                    if not line: continue
                        
                    if "bpf_trace_printk" in line:
                        parts = line.split("bpf_trace_printk:")
                        if len(parts) > 1:
                            content = parts[1].strip()
                            if "[ALERT]" in content:
                                self.log(f"🚨 {content}")
                                self.root.after(0, lambda m=content: self.show_alert(m))
        except Exception as e:
            self.log(f"[!] Monitor Error: {e}")

    def shutdown(self):
        self.running = False
        subprocess.run(["rm", "-f", BPF_PATH])
        self.root.quit()

if __name__ == "__main__":
    if not os.path.exists("exec_monitor.o"):
        print("Error: exec_monitor.o not found! Compile it first.")
        sys.exit(1)
        
    root = tk.Tk()
    app = SentinelApp(root)
    root.protocol("WM_DELETE_WINDOW", app.shutdown)
    root.mainloop()
