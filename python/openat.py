#!/usr/bin/python3

from bcc import BPF

# eBPF program that hooks into the openat syscall
bpf_code = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    char fname[256];
};

BPF_PERF_OUTPUT(events);
int trace_openat(struct pt_regs *ctx, int dfd, const char __user *filename, int flags) {
    struct data_t data = {};

    // Capture process ID and name
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // Capture file name
    bpf_probe_read_user(&data.fname, sizeof(data.fname), filename);

    // Send the data to user-space
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""
# Load the eBPF program
b = BPF(text=bpf_code)

# Attach eBPF program to the openat syscall
# b.attach_kprobe(event="sys_openat", fn_name="trace_openat")
b.attach_tracepoint(tp="syscalls:sys_enter_openat", fn_name="trace_openat")

# Function to print the output
def print_event(cpu, data, size):
    event = b["events"].event(data)
    print(f"PID: {event.pid}, Process: {event.comm.decode('utf-8')}, File: {event.fname.decode('utf-8', 'replace')}")

# Open a perf buffer to receive events from kernel space
b["events"].open_perf_buffer(print_event)

# Continuously listen for events and print them
while True:
    b.perf_buffer_poll()