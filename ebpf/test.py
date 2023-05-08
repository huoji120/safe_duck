from bcc import BPF
from time import sleep

# eBPF program to trace process creation and exit
program = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct event_data_t {
    int type;
    u32 pid;
    u32 ppid;
} __attribute__((packed));

BPF_PERF_OUTPUT(events);

int trace_process_start(struct pt_regs *ctx, struct filename *filename) {
    struct event_data_t event_data;

    u32 pid = bpf_get_current_pid_tgid();
    u32 ppid = bpf_get_current_pid_tgid() >> 32;
    event_data.type = 0;
    event_data.pid = pid;
    event_data.ppid = ppid;
    events.perf_submit(ctx, &event_data, sizeof(event_data));
    return 0;
}

int trace_process_exit(struct pt_regs *ctx) {
    struct event_data_t event_data;

    u32 pid = bpf_get_current_pid_tgid();
    u32 ppid = bpf_get_current_pid_tgid() >> 32;
    event_data.type = 1;
    event_data.pid = pid;
    event_data.ppid = ppid;
    events.perf_submit(ctx, &event_data, sizeof(event_data));

    return 0;
}
"""

# initialize BPF and attach tracepoints
b = BPF(text=program)
b.attach_kprobe(event=b.get_syscall_fnname("execve"), fn_name="trace_process_start")
b.attach_kprobe(event=b.get_syscall_fnname("exit_group"), fn_name="trace_process_exit")

import psutil

def get_process_path(pid):
    try:
        proc = psutil.Process(pid)
        return proc.exe()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return "unknown"

# process event data
def print_event(cpu, data, size):
    event = b["events"].event(data)
    path = get_process_path(event.pid)
    print(f"type: {event.type} pid: {event.pid}, ppid: {event.ppid} path: {path}")

b["events"].open_perf_buffer(print_event)

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit() 
