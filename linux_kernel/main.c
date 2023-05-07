#include "head.h"

struct safe_duck_dev {
    wait_queue_head_t read_wait;
};

unsigned int network_callback(const struct nf_hook_ops *ops,
                              struct sk_buff *skb, const struct net_device *in,
                              const struct net_device *out,
                              int (*okfn)(struct sk_buff *)) {
    do {
        if (skb == NULL) {
            break;
        }
        struct iphdr *ip_header = ip_hdr(skb);

        if (ip_header == NULL) {
            break;
        }
        // push ip address to list
        struct kernel_msg_t *msg =
            kmalloc(sizeof(struct kernel_msg_t), GFP_KERNEL);
        if (msg == NULL) {
            printk(KERN_ERR "Failed to allocate memory for new msg\n");
            break;
        }
        msg->type = SD_MSG_TYPE_NEW_IP_CONNECT;
        msg->u.poll_req.src_ip = ip_header->saddr;
        push_msg(msg);
    } while (false);

    return NF_ACCEPT;
}
unsigned int driver_poll_callback(struct file *filep,
                                  struct poll_table_struct *wait) {
    unsigned int mask = 0;
    g_is_r3_ready = false;
    poll_wait(filep, &g_r3_wait_queue, wait);
    g_is_r3_ready = true;
    if (get_msg_list_length() != 0) {
        mask |= POLLIN | POLLRDNORM;
    }

    return mask;
}
int safe_duck_release(struct inode *inode, struct file *file) { return 0; }
ssize_t safe_duck_read(struct file *file, char __user *buf, size_t count,
                       loff_t *pos) {
    if (count < sizeof(struct kernel_msg_t)) {
        return 0;
    }
    struct kernel_msg_t *msg = get_msg();
    if (msg == NULL) {
        return 0;
    }
    int ret = copy_to_user(buf, msg, sizeof(struct kernel_msg_t));
    kfree(msg);
    if (ret != 0) {
        printk(KERN_ERR "Failed to copy msg to user space\n");
    }
    return ret;
}

int safe_duck_open(struct inode *inode, struct file *filep) { return 0; }
bool build_dev(void) {
    int rc = alloc_chrdev_region(&g_driver_dev_build.devid, 0, DEVICE_CNT,
                                 DEVICE_NAME);
    g_driver_dev_build.major = MAJOR(g_driver_dev_build.devid);
    g_driver_dev_build.minor = MINOR(g_driver_dev_build.devid);
    if (rc < 0) {
        printk("newchrled chr_dev region err\n");
        return false;
    }
    printk(KERN_WARNING "major:%d, minor:%d\n", g_driver_dev_build.major,
           g_driver_dev_build.minor);
    cdev_init(&g_driver_dev_build.cdev, &g_fops);
    rc = cdev_add(&g_driver_dev_build.cdev, g_driver_dev_build.devid,
                  DEVICE_CNT);
    g_driver_dev_build.class = class_create(THIS_MODULE, DEVICE_NAME);
    if (IS_ERR(g_driver_dev_build.class)) {
        return false;
    }
    g_driver_dev_build.device =
        device_create(g_driver_dev_build.class, NULL, g_driver_dev_build.devid,
                      NULL, DEVICE_NAME);
    return IS_ERR(g_driver_dev_build.device) == false;
}
void destory_dev(void) {
    cdev_del(&g_driver_dev_build.cdev);
    unregister_chrdev_region(g_driver_dev_build.devid, DEVICE_NAME);
    device_destroy(g_driver_dev_build.class, g_driver_dev_build.devid);
    class_destroy(g_driver_dev_build.class);
}
static int __init driver_entry(void) {
    printk(KERN_WARNING "[DebugMessage] safe duck init\n");

    // Initialize list of addresses
    if (build_dev() == false) {
        printk(KERN_ERR "Failed to build device\n");
        return -1;
    }
    init_msg();
    int rc = nf_register_net_hook(&init_net, &g_network_hook_ops);
    if (rc < 0) {
        printk(KERN_ERR "Failed to register network hook: %d\n", rc);
        return rc;
    }
    printk(KERN_WARNING "[DebugMessage] safe duck init success \n");
    return 0;
}

static void __exit driver_exit(void) {
    printk(KERN_INFO "[DebugMessage] safe duck exit\n");
    nf_unregister_net_hook(&init_net, &g_network_hook_ops);
    cleanup_msg();
    destory_dev();
}

module_init(driver_entry);
module_exit(driver_exit);
