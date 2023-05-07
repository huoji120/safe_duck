#include "head.h"

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

ssize_t safe_duck_write(struct file *filp, const char __user *buf, size_t count,
                        loff_t *f_pos) {
    if (count > sizeof(struct client_msg_t)) {
        return -EINVAL;
    }
    struct client_msg_t *message =
        kmalloc(sizeof(struct client_msg_t), GFP_KERNEL);
    do {
        if (message == NULL) {
            printk(KERN_ERR "Failed to allocate memory for new msg\n");
            break;
        }
        if (copy_from_user(message, buf, sizeof(struct client_msg_t))) {
            return -EFAULT;
        }
        if (message->check_sum != MSG_CHECK_SUM) {
            printk(KERN_ERR "Invalid checksum\n");
            break;
        }
        dispath_client_msg(message);
    } while (false);
    if (message != NULL) {
        kfree(message);
    }
    return count;
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
    g_driver_dev_build.init_chrdev_region = true;

    printk(KERN_WARNING "major:%d, minor:%d\n", g_driver_dev_build.major,
           g_driver_dev_build.minor);
    cdev_init(&g_driver_dev_build.cdev, &g_fops);
    rc = cdev_add(&g_driver_dev_build.cdev, g_driver_dev_build.devid,
                  DEVICE_CNT);
    g_driver_dev_build.class = class_create(THIS_MODULE, DEVICE_NAME);
    if (IS_ERR(g_driver_dev_build.class)) {
        return false;
    }
    g_driver_dev_build.init_cdev_add = true;
    g_driver_dev_build.device =
        device_create(g_driver_dev_build.class, NULL, g_driver_dev_build.devid,
                      NULL, DEVICE_NAME);
    const bool build_dev_success = IS_ERR(g_driver_dev_build.device) == false;
    if (build_dev_success) {
        g_driver_dev_build.init_device_create = true;
    }
    return build_dev_success;
}
void destory_dev(void) {
    if (g_driver_dev_build.init_cdev_add) {
        cdev_del(&g_driver_dev_build.cdev);
    }
    if (g_driver_dev_build.init_chrdev_region) {
        unregister_chrdev_region(g_driver_dev_build.devid, DEVICE_NAME);
    }
    if (g_driver_dev_build.init_device_create) {
        device_destroy(g_driver_dev_build.class, g_driver_dev_build.devid);
    }
    if (g_driver_dev_build.init_cdev_add) {
        class_destroy(g_driver_dev_build.class);
    }
}
int cleanup(void) {
    if (g_driver_dev_build.init_netfilter) {
        nf_unregister_net_hook(&init_net, &g_network_hook_ops);
    }
    if (g_driver_dev_build.init_hashmap) {
        cleanup_iphashmap();
    }
    destory_dev();
    cleanup_msg();
    return -1;
}
static int __init driver_entry(void) {
    printk(KERN_WARNING "[DebugMessage] safe duck init\n");

    // Initialize list of addresses
    if (build_dev() == false) {
        printk(KERN_ERR "Failed to build device\n");
        return -1;
    }
    if (init_ip_hashmap() == false) {
        printk(KERN_ERR "Failed to init ip hashmap\n");
        return cleanup();
    }
    g_driver_dev_build.init_hashmap = true;
    init_msg();
    int rc = nf_register_net_hook(&init_net, &g_network_hook_ops);
    if (rc < 0) {
        printk(KERN_ERR "Failed to register network hook: %d\n", rc);
        return cleanup();
    }
    g_driver_dev_build.init_netfilter = true;
    printk(KERN_WARNING "[DebugMessage] safe duck init success \n");
    return 0;
}

static void __exit driver_exit(void) {
    printk(KERN_INFO "[DebugMessage] safe duck exit\n");
    cleanup();
}

module_init(driver_entry);
module_exit(driver_exit);
