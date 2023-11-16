#pragma once
#include "head.h"
#define MSG_CHECK_SUM 1337
typedef enum _msg_type {
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
typedef struct msg_list {
    struct list_head node;
    struct kernel_msg_t *msg;
};

extern void push_msg(struct kernel_msg_t *msg);
extern struct kernel_msg_t *get_msg(void);
extern size_t get_msg_list_length(void);
extern void cleanup_msg(void);
extern void init_msg(void);
extern void push_msg_syn_attack(u32 ip_address);
extern void push_msg_new_ip_connect(u32 ip_address);
extern void push_msg_ssh_bf_attack(u32 ip_address);
