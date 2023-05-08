#include "msg.h"
namespace client_msg {
int driver_read;
int driver_write;
auto call_driver(client_msg_t msg) -> bool {
    int is_success = write(driver_write, &msg, sizeof(client_msg_t));
    if (is_success == 0) {
        perror("Failed to write message to safe_duck device");
        return false;
    }
    return true;
}
auto block_ip(uint32_t ip_address, size_t time_sec) -> bool {
    client_msg_t msg;
    msg.check_sum = MSG_CHECK_SUM;
    msg.type = SD_MSG_TYPE_CLIENT_BLOCK_IP;
    msg.u.ip_address.src_ip = ip_address;
    msg.u.ip_address.block_time = time_sec;
    return call_driver(msg);
}
auto dispath_kernel_msg_i(_msg_type type, kernel_msg_t msg) -> void {
    switch (type) {
        case SD_MSG_TYPE_NEW_IP_CONNECT: {
            auto ip_str = tools::cover_ip(msg.u.ip_action.src_ip);
            printf("New IP connection: %s\n", ip_str.c_str());
        } break;
        case SD_MSG_TYPE_SYN_ATTACK: {
            auto ip_str = tools::cover_ip(msg.u.ip_action.src_ip);
            printf("Block ip for syn attack: %s \n", ip_str.c_str());
        } break;
        case SD_MSG_TYPE_SSH_BF_ATTACK: {
            auto ip_str = tools::cover_ip(msg.u.ip_action.src_ip);
            printf("Block ip for SSH brute force attack: %s \n",
                   ip_str.c_str());
        } break;
        default:
            printf("Unknown message type: %d\n", msg.type);
            break;
    }
}

auto dispath_kernel_msg() -> void {
    int fd = driver_read;
    while (1) {
        struct pollfd fds[1];
        fds[0].fd = fd;
        fds[0].events = POLLIN;
        printf("Waiting for message from safe_duck device...\n");
        int ret = poll(fds, 1, -1);
        if (ret < 0) {
            perror("poll failed");
            close(fd);
            return;
        }
        printf("Got message from safe_duck device\n");
        if (fds[0].revents & POLLIN) {
            kernel_msg_t msg;
            int is_success = read(fd, &msg, sizeof(kernel_msg_t));
            if (is_success == 0 && msg.check_sum == MSG_CHECK_SUM) {
                dispath_kernel_msg_i((_msg_type)msg.type, msg);
            } else {
                perror("Failed to read message from safe_duck device");
            }
        }
    }
}
auto init() -> bool {
    driver_read = open("/dev/safe_duck", O_RDWR);
    if (driver_read < 0) {
        perror("Failed to open safe_duck device");
        return false;
    }
    driver_write = open("/dev/safe_duck", O_RDWR);
    if (driver_write < 0) {
        perror("Failed to open safe_duck device");
        return false;
    }
    return true;
}
auto uninstall() -> void {
    if (driver_write) {
        close(driver_write);
        driver_write = 0;
    }
    if (driver_read) {
        close(driver_read);
        driver_read = 0;
    }
}
}  // namespace client_msg
