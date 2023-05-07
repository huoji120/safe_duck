#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <unistd.h>
#define MSG_CHECK_SUM 1337
typedef enum _msg_type {
    SD_MSG_TYPE_ERROR = -1,
    SD_MSG_TYPE_NEW_IP_CONNECT = 0,
};

typedef struct kernel_msg_t {
    unsigned long check_sum;
    int type;
    union {
        struct {
            unsigned int src_ip;
        } poll_req;
    } u;
};
auto cover_ip(unsigned int ip) -> std::string {
    std::string ip_str;
    ip_str = std::to_string(ip & 0xff) + "." +
             std::to_string((ip >> 8) & 0xff) + "." +
             std::to_string((ip >> 16) & 0xff) + "." +
             std::to_string((ip >> 24) & 0xff);
    return ip_str;
}
int main() {
    int fd = open("/dev/safe_duck", O_RDWR);
    if (fd < 0) {
        perror("Failed to open safe_duck device");
        return 1;
    }

    while (1) {
        struct pollfd fds[1];
        fds[0].fd = fd;
        fds[0].events = POLLIN;
        printf("Waiting for message from safe_duck device...\n");
        int ret = poll(fds, 1, -1);
        if (ret < 0) {
            perror("poll failed");
            close(fd);
            return 1;
        }
        printf("Got message from safe_duck device\n");
        if (fds[0].revents & POLLIN) {
            kernel_msg_t msg;
            int is_success = read(fd, &msg, sizeof(kernel_msg_t));
            if (is_success == 0 && msg.check_sum == MSG_CHECK_SUM) {
                if (msg.type == SD_MSG_TYPE_NEW_IP_CONNECT) {
                    auto ip_str = cover_ip(msg.u.poll_req.src_ip);
                    printf("New IP connection: %s\n", ip_str.c_str());

                } else {
                    printf("Unknown message type: %d\n", msg.type);
                }
            } else {
                perror("Failed to read message from safe_duck device");
            }
        }
    }

    close(fd);
    return 0;
}
