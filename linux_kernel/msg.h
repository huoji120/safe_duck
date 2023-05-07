#pragma once
#include "head.h"
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
typedef struct msg_list {
    struct list_head node;
    struct kernel_msg_t *msg;
};

extern void push_msg(struct kernel_msg_t *msg);
extern struct kernel_msg_t *get_msg(void);
extern size_t get_msg_list_length(void);
extern void cleanup_msg(void);
extern void init_msg(void);
