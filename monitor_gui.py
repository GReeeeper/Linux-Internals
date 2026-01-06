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
        self.root.geometry("700x600")
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
        
        self.log_area = scrolledtext.ScrolledText(frame_log, width=80, height=15, 
                                                  bg="#000000", fg="#00cc00", font=("Consolas", 10),
                                                  insertbackground="#00ff00", borderwidth=0)
        self.log_area.pack(fill=tk.BOTH, expand=True)
        self.log_area.insert(tk.END, "[*] SYSTEM INITIALIZING... PROBE LOADING...\n")

        # Unload Button
        self.btn_quit = tk.Button(root, text="[ DEACTIVATE PROBE ]", command=self.shutdown, 
                                  bg="#440000", fg="#ffaaaa", font=("Consolas", 11, "bold"), relief=tk.FLAT)
        self.btn_quit.pack(pady=5, ipadx=10)

        # Simulation Button (For Demo)
        self.btn_sim = tk.Button(root, text="[ SIMULATE THREAT ]", command=self.simulate_threat,
                                 bg="#333", fg="yellow", font=("Consolas", 10, "bold"), relief=tk.FLAT)
        self.btn_sim.pack(pady=10, ipadx=10)

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


    def simulate_threat(self):
        # Trigger a fake network alert
        self.handle_network_alert("[NETWORK] INBOUND ncat 3232235876:4444") 
        self.log("[TEST] Simulated Inbound Connection from 192.168.1.100")

    def reset_alert(self):
        self.root.configure(bg="#050505")
        self.header.configure(bg="#050505", fg="#00ff00", text="::: KERNEL SENTINEL ACTIVE :::")

    def monitor_loop(self):
        self.log("[*] Monitoring Trace Pipe for Network & Process Events...")
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
                            elif "[NETWORK]" in content:
                                self.handle_network_alert(content)
                                
        except Exception as e:
            self.log(f"[!] Monitor Error: {e}")

    def handle_network_alert(self, msg):
        # Format: [NETWORK] DIR COMM IP_INT:PORT
        try:
            parts = msg.split()
            if len(parts) < 4: return
            
            direction = parts[1] # INBOUND or OUTBOUND
            comm = parts[2]
            ip_port = parts[3]
            
            if ":" in ip_port:
                ip_int_str, port = ip_port.split(":")
                
                # Decode IP
                import socket, struct
                ip_str = socket.inet_ntoa(struct.pack("<I", int(ip_int_str)))
                
                log_msg = f"[NET] {direction} | {comm} | {ip_str}:{port}"
                self.root.after(0, lambda: self.log(log_msg))

                # Trigger Logic: 
                # 1. INBOUND from outside (checking if IP is not 127.0.0.1 which eBPF filters, but let's be safe)
                # 2. OUTBOUND from suspicious process
                
                is_suspicious_proc = comm in ["ncat", "nmap", "nc", "bash", "python", "python3", "curl", "wget"]
                
                if direction == "INBOUND" or is_suspicious_proc:
                     self.root.after(0, lambda: self.show_blocking_prompt(direction, comm, ip_str))

        except Exception as e:
            print(f"Parse Error: {e}")

    def show_blocking_prompt(self, direction, comm, ip):
        top = tk.Toplevel(self.root)
        top.title("⚠️ NETWORK INTRUSION DETECTED")
        top.geometry("450x300")
        top.configure(bg="#200000")
        
        tk.Label(top, text="!!! UNAUTHORIZED CONNECTION !!!", font=("Impact", 16), fg="red", bg="#200000").pack(pady=10)
        
        info = f"Direction: {direction}\nProcess: {comm}\nRemote IP: {ip}"
        tk.Label(top, text=info, font=("Consolas", 12), fg="white", bg="#200000", justify=tk.LEFT).pack(pady=10)
        
        # Action Buttons
        btn_frame = tk.Frame(top, bg="#200000")
        btn_frame.pack(pady=20)
        
        tk.Button(btn_frame, text=f"[ BLOCK IP {ip} ]", bg="red", fg="white", font=("Consolas", 11, "bold"),
                  command=lambda: self.block_ip(ip, top)).pack(side=tk.LEFT, padx=10)
                  
        tk.Button(btn_frame, text="[ ALLOW ]", bg="#333", fg="lime", font=("Consolas", 11, "bold"),
                  command=top.destroy).pack(side=tk.LEFT, padx=10)

    def block_ip(self, ip, window):
        try:
            # Execute iptables command
            # sudo iptables -A INPUT -s IP -j DROP
            subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            self.log(f"🛡️ [DEFENSE] BLOCKED IP PERMANENTLY: {ip}")
            window.destroy()
        except Exception as e:
            self.log(f"[!] Start Monitor Error: {e}")
            messagebox.showerror("Block Error", str(e))

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
