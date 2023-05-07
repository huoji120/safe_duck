#include "client_msg.h"

void dispath_client_msg(struct client_msg_t* msg) {
    switch (msg->type) {
        case SD_MSG_TYPE_CLIENT_BLOCK_IP:
            const size_t target_ip_address = msg->u.ip_address.src_ip;
            const size_t block_time = msg->u.ip_address.block_time;
            block_ip_address(target_ip_address, block_time);
            break;
        default:
            printk(KERN_INFO "Unknown msg type: %d\n", msg->type);
            break;
    }
}
