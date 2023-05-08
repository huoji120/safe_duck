#include <iostream>
#include <string>
#include <unistd.h>
#include <fstream>
#include <vector>
#include <bcc/BPF.h>
#include <signal.h>
#include <sstream>

const std::string EBPF_SOURCE_PATH = "core.ebpf.c";

volatile bool interrupted = false;

void signal_handler(int signal) { interrupted = true; }

std::pair<bool, std::string> get_process_path(int pid) {
    try {
        char path[4096] = {0};
        std::string symlink_path = "/proc/" + std::to_string(pid) + "/exe";
        ssize_t len = readlink(symlink_path.c_str(), path, sizeof(path));
        if (len != -1) {
            return {true, std::string(path)};
        }
    } catch (...) {
    }
    return {false, "unknown"};
}

std::string get_process_name(pid_t pid) {
    std::string process_name;
    std::ifstream comm_file("/proc/" + std::to_string(pid) + "/comm");

    if (comm_file.is_open()) {
        std::getline(comm_file, process_name);
        comm_file.close();
    } else {
        process_name = "unknown";
    }

    return process_name;
}

std::string get_process_cmdline(pid_t pid) {
    std::string cmdline;
    std::ifstream cmdline_file("/proc/" + std::to_string(pid) + "/cmdline");

    if (cmdline_file.is_open()) {
        std::getline(cmdline_file, cmdline, '\0');
        cmdline_file.close();
    } else {
        cmdline = "unknown";
    }

    return cmdline;
}
void print_event(void *context, void *data, int data_size) {
    struct event_data_t {
        int type;
        uint32_t pid;
        uint32_t ppid;
    };

    auto event = static_cast<event_data_t *>(data);
    auto [process_exists, path] = get_process_path(event->pid);
    if (event->type == 0 && process_exists == false) {
        // 进程启动如果路径为空说明取不到了
        // 进程结束路径一定是取不到的
        return;
    }
    auto process_name = get_process_name(event->pid);
    auto cmdline = get_process_cmdline(event->pid);
    auto event_type = event->type == 0 ? "start" : "exit";
    printf("type: %s pid: %d ppid: %d path: %s name: %s cmdline: %s\n",
           event_type, event->pid, event->ppid, path.c_str(),
           process_name.c_str(), cmdline.c_str());
}

int main() {
    ebpf::BPF bpf;
    std::ifstream ebpf_file(EBPF_SOURCE_PATH, std::ios::binary);
    // 检查文件是否存在
    if (ebpf_file.fail()) {
        std::cerr << "Failed to open " << EBPF_SOURCE_PATH << std::endl;
        return 1;
    }
    std::vector<char> ebpf_program((std::istreambuf_iterator<char>(ebpf_file)),
                                   std::istreambuf_iterator<char>());
    auto init_res =
        bpf.init(std::string(ebpf_program.data(), ebpf_program.size()));
    if (init_res.code() != 0) {
        std::cerr << "Failed to initialize BPF program: " << init_res.msg()
                  << std::endl;
        return 1;
    }

    std::string execve_fnname = bpf.get_syscall_fnname("execve");
    std::string exit_group_fnname = bpf.get_syscall_fnname("exit_group");

    auto attach_res1 = bpf.attach_kprobe(execve_fnname, "trace_process_start");
    auto attach_res2 =
        bpf.attach_kprobe(exit_group_fnname, "trace_process_exit");

    if (attach_res1.code() != 0 || attach_res2.code() != 0) {
        std::cerr << "Failed to attach kprobes: " << attach_res1.msg() << " "
                  << attach_res2.msg() << std::endl;
        return 1;
    }

    signal(SIGINT, signal_handler);

    auto ret =
        bpf.open_perf_buffer("events", print_event, nullptr, nullptr, 256);
    if (ret.code() != 0) {
        fprintf(stderr, "Error: open_perf_buffer: %s\n", ret.msg().c_str());
        return EXIT_FAILURE;
    }
    auto table = bpf.get_table("events");
    auto perf_buffer = bpf.get_perf_buffer("events");

    while (!interrupted) {
        perf_buffer->poll(1000);
    }

    return 0;
}
