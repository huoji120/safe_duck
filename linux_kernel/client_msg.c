#include "client_msg.h"

void dispath_client_msg(struct client_msg_t* msg) {
    uint32_t target_ip_address;
    size_t block_time;
    switch (msg->type) {
        case SD_MSG_TYPE_CLIENT_BLOCK_IP:
            target_ip_address = msg->u.ip_address.src_ip;
            block_time = msg->u.ip_address.block_time;
            block_ip_address(target_ip_address, block_time);
            break;
        case SD_MSG_TYPE_CLIENT_UNBLOCK_IP:
            target_ip_address = msg->u.ip_address.src_ip;
            unblock_ip_address(target_ip_address);
            break;
        default:
            printk(KERN_INFO "Unknown msg type: %d\n", msg->type);
            break;
    }
}
