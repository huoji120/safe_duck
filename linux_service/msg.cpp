#include "msg.h"
namespace client_msg {
int driver_read;
int driver_write;
auto call_driver(client_msg_t msg) -> bool {
    int is_success = write(driver_write, &msg, sizeof(client_msg_t));
    if (is_success == 0) {
        ERROR("Failed to write message to safe_duck device");
        return false;
    }
    return true;
}
auto dispath_kernel_msg_i(_msg_type type, kernel_msg_t msg) -> void {
    switch (type) {
        case _msg_type::SD_MSG_TYPE_NEW_IP_CONNECT:
        case _msg_type::SD_MSG_TYPE_SYN_ATTACK:
        case _msg_type::SD_MSG_TYPE_SSH_BF_ATTACK: {
            network_event::on_event(type, msg);
        } break;
        default:
            LOG("Unknown message type: %d\n", msg.type);
            break;
    }
}

auto dispath_kernel_msg() -> void {
    int fd = driver_read;
    while (1) {
        struct pollfd fds[1];
        fds[0].fd = fd;
        fds[0].events = POLLIN;
        LOG("Waiting for message from safe_duck device...\n");
        int ret = poll(fds, 1, -1);
        if (ret < 0) {
            ERROR("poll failed");
            close(fd);
            return;
        }
        LOG("Got message from safe_duck device\n");
        if (fds[0].revents & POLLIN) {
            kernel_msg_t msg;
            int is_success = read(fd, &msg, sizeof(kernel_msg_t));
            if (is_success == 0 && msg.check_sum == MSG_CHECK_SUM) {
                dispath_kernel_msg_i((_msg_type)msg.type, msg);
            } else {
                ERROR("Failed to read message from safe_duck device");
            }
        }
    }
}
auto init() -> bool {
    driver_read = open("/dev/safe_duck", O_RDWR);
    if (driver_read < 0) {
        ERROR("Failed to open safe_duck device");
        return false;
    }
    driver_write = open("/dev/safe_duck", O_RDWR);
    if (driver_write < 0) {
        ERROR("Failed to open safe_duck device");
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
