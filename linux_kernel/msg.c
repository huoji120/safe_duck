#include "head.h"
struct msg_list g_msg_list;
spinlock_t g_msg_lock;
size_t g_msg_length;
void push_msg(struct kernel_msg_t *msg) {
    if (get_msg_list_length() > 0x1000) {
        printk(KERN_ERR "Too many messages in the list\n");
        kfree(msg);
        return;
    }
    struct msg_list *new_msg = kmalloc(sizeof(struct msg_list), GFP_KERNEL);
    if (new_msg == NULL) {
        printk(KERN_ERR "Failed to allocate memory for new msg\n");
        return;
    }
    new_msg->msg = msg;
    new_msg->msg->check_sum = MSG_CHECK_SUM;
    spin_lock_bh(&g_msg_lock);
    list_add_tail(&new_msg->node, &g_msg_list.node);
    g_msg_length++;
    spin_unlock_bh(&g_msg_lock);
    if (g_is_r3_ready) {
        wake_up_interruptible(&g_r3_wait_queue);
    }
}
void push_msg_new_ip_connect(u32 ip_address) {
    struct kernel_msg_t *msg = kmalloc(sizeof(struct kernel_msg_t), GFP_KERNEL);
    if (msg == NULL) {
        printk(KERN_ERR "Failed to allocate memory for new msg\n");
        return;
    }
    msg->type = SD_MSG_TYPE_NEW_IP_CONNECT;
    msg->u.ip_action.src_ip = ip_address;
    push_msg(msg);
}
void push_msg_syn_attack(u32 ip_address) {
    struct kernel_msg_t *msg = kmalloc(sizeof(struct kernel_msg_t), GFP_KERNEL);
    if (msg == NULL) {
        printk(KERN_ERR "Failed to allocate memory for new msg\n");
        return;
    }
    msg->type = SD_MSG_TYPE_SYN_ATTACK;
    msg->u.ip_action.src_ip = ip_address;
    push_msg(msg);
}
void push_msg_ssh_bf_attack(u32 ip_address) {
    struct kernel_msg_t *msg = kmalloc(sizeof(struct kernel_msg_t), GFP_KERNEL);
    if (msg == NULL) {
        printk(KERN_ERR "Failed to allocate memory for new msg\n");
        return;
    }
    msg->type = SD_MSG_TYPE_SSH_BF_ATTACK;
    msg->u.ip_action.src_ip = ip_address;
    push_msg(msg);
}
struct kernel_msg_t *get_msg(void) {
    struct kernel_msg_t *msg = NULL;
    struct msg_list *tmp = NULL;
    spin_lock_bh(&g_msg_lock);
    if (list_empty(&g_msg_list.node)) {
        spin_unlock_bh(&g_msg_lock);
        return NULL;
    }
    tmp = list_first_entry(&g_msg_list.node, struct msg_list, node);
    list_del(&tmp->node);
    g_msg_length--;
    spin_unlock_bh(&g_msg_lock);
    msg = tmp->msg;
    kfree(tmp);
    return msg;
}
size_t get_msg_list_length(void) {
    size_t len = 0;
    spin_lock_bh(&g_msg_lock);
    len = g_msg_length;
    spin_unlock_bh(&g_msg_lock);
    return len;
}
void cleanup_msg(void) {
    struct msg_list *tmp = NULL;
    struct msg_list *next = NULL;
    spin_lock_bh(&g_msg_lock);
    list_for_each_entry_safe(tmp, next, &g_msg_list.node, node) {
        list_del(&tmp->node);
        kfree(tmp->msg);
        kfree(tmp);
    }
    g_msg_length = 0;
    spin_unlock_bh(&g_msg_lock);
}
void init_msg(void) {
    INIT_LIST_HEAD(&(g_msg_list.node));
    spin_lock_init(&g_msg_lock);
    g_msg_length = 0;
}
EXPORT_SYMBOL(push_msg);
EXPORT_SYMBOL(get_msg);
EXPORT_SYMBOL(get_msg_list_length);
EXPORT_SYMBOL(cleanup_msg);
EXPORT_SYMBOL(init_msg);
