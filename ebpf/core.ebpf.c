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
