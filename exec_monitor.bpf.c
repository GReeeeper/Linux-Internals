#define __TARGET_ARCH_x86
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Helper to read string from pt_regs (Accessing syscall arg 1)
static __always_inline void read_syscall_filename(struct pt_regs *regs, char *buf, size_t sz) {
    char *filename_ptr;
    // On x86_64, the first syscall argument is in 'di'
    // We strictly read kernel memory to get the pointer address from the struct
    bpf_probe_read_kernel(&filename_ptr, sizeof(filename_ptr), &regs->di);
    
    // Then read the string from user space (pointer points to user mem)
    bpf_probe_read_user_str(buf, sz, filename_ptr);
}

// Simple string containment check helper
// Returns 1 if 'needle' is found in 'haystack'
static __always_inline int contains(const char *haystack, const char *needle) {
    // Unrolled loop or limited check would be ideal, but for PoC we check specific offsets
    // This is hard in BPF without loops. 
    // Instead, we will look for exact matches at the end of the string or common paths.
    
    // Actually, let's just do a naive check for the specific keywords we care about
    // by manually unrolling comparison for known offsets is too brittle.
    
    // Better approach for BPF: Check if these specific byte sequences exist 
    // We can loop over the string carefully.
    
    char h;
    char n;
    
    #pragma unroll
    for (int i = 0; i < 30; i++) {
        h = haystack[i];
        if (h == 0) break;
        
        // Check if needle matches starting here
        int match = 1;
        #pragma unroll
        for (int j = 0; j < 6; j++) { // Max keyword length ~6
            n = needle[j];
            if (n == 0) break; // End of needle, match found!
            if (haystack[i+j] != n) {
                match = 0;
                break;
            }
        }
        if (match && needle[0] != 0) return 1;
    }
    return 0;
}

static __always_inline void check_malicious(const char *fname) {
    // List of "Bad" keywords
    // We use short keywords to keep unrolled loops small
    
    // 1. Recon
    if (contains(fname, "whoami")) {
        bpf_printk("[ALERT] Recon Detected (whoami): %s\n", fname);
        return;
    }
    if (contains(fname, "id")) {
        // "id" is too short, might match "android", "idea". 
        // Let's be specific for short ones: "/bin/id", "/usr/bin/id"
        // Or check if it ends with /id.
        // For this PoC, let's skip "id" to avoid noise or be very careful.
    }
    
    // 2. Network / Exfiltration
    if (contains(fname, "nc")) { 
        // "nc" is very short (sync, func)... risky. 
        // Let's check for "ncat" or "netcat"
    }
    if (contains(fname, "ncat")) {
        bpf_printk("[ALERT] Netcat Detected: %s\n", fname);
        return;
    }
    if (contains(fname, "nmap")) {
        bpf_printk("[ALERT] Port Scanning Detected (nmap): %s\n", fname);
        return;
    }
    if (contains(fname, "tcpdump")) {
        bpf_printk("[ALERT] Sniffing Detected (tcpdump): %s\n", fname);
        return;
    }
    
    // 3. Persistence / PrivEsc
    if (contains(fname, "insmod")) {
        bpf_printk("[ALERT] Kernel Module Loading (insmod): %s\n", fname);
        return;
    }
}

// 1. Hook for standard execve
// __x64_sys_execve(struct pt_regs *regs)
SEC("kprobe/__x64_sys_execve")
int BPF_KPROBE(kprobe_execve, struct pt_regs *regs)
{
    char fname[32] = {};
    read_syscall_filename(regs, fname, sizeof(fname));
    
    check_malicious(fname);
    return 0;
}

// 2. Hook for execveat
// __x64_sys_execveat(struct pt_regs *regs)
SEC("kprobe/__x64_sys_execveat")
int BPF_KPROBE(kprobe_execveat, struct pt_regs *regs)
{
    char *filename_ptr;
    bpf_probe_read_kernel(&filename_ptr, sizeof(filename_ptr), &regs->si);

    char fname[32] = {};
    bpf_probe_read_user_str(&fname, sizeof(fname), filename_ptr);
    
    check_malicious(fname);
// 3. Hook for openat (File Access)
// __x64_sys_openat(int dfd, const char *filename, int flags, umode_t mode)
// Args: di, si, dx, r10
SEC("kprobe/__x64_sys_openat")
int BPF_KPROBE(kprobe_openat, struct pt_regs *regs)
{
    char *filename_ptr;
    // buffer for filename
    char fname[32] = {};
    
    // Arg1 (filename) is in SI
    bpf_probe_read_kernel(&filename_ptr, sizeof(filename_ptr), &regs->si);
    bpf_probe_read_user_str(&fname, sizeof(fname), filename_ptr);
    
    // Check for sensitive files
    if (contains(fname, "shadow")) {
        bpf_printk("[ALERT] Sensitive File Access (/etc/shadow): %s\n", fname);
    }
    if (contains(fname, "passwd")) {
         // Only flag if opening for write? checking flags is hard in string matching
         // Let's just flag all access for now as "Suspicious"
         bpf_printk("[ALERT] Sensitive File Access (/etc/passwd): %s\n", fname);
    }
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
