#pragma once
#include "head.h"
#define MSG_CHECK_SUM 1337

enum class _msg_type {
    SD_MSG_TYPE_ERROR = -1,
    SD_MSG_TYPE_NEW_IP_CONNECT = 0,
    SD_MSG_TYPE_SYN_ATTACK = 1,
    SD_MSG_TYPE_CLIENT_BLOCK_IP = 2,
    SD_MSG_TYPE_SSH_BF_ATTACK = 3,
    SD_MSG_TYPE_CLIENT_UNBLOCK_IP = 4,
};
typedef struct kernel_msg_t {
    unsigned long check_sum;
    int type;
    union {
        struct {
            unsigned int src_ip;
        } ip_action;
    } u;
};
typedef struct client_msg_t {
    unsigned long check_sum;
    int type;
    union {
        struct {
            unsigned int src_ip;
            unsigned long block_time;
        } ip_address;
    } u;
};
namespace client_msg {
auto dispath_kernel_msg() -> void;
auto block_ip(uint32_t ip_address, size_t time_sec) -> bool;
auto init() -> bool;
auto call_driver(client_msg_t msg) -> bool;
auto uninstall() -> void;
}  // namespace client_msg
