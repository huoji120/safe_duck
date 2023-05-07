#pragma once
#include "head.h"
extern unsigned int network_callback(const struct nf_hook_ops *ops,
                                     struct sk_buff *skb,
                                     const struct net_device *in,
                                     const struct net_device *out,
                                     int (*okfn)(struct sk_buff *));
extern unsigned int driver_poll_callback(struct file *filep,
                                         struct poll_table_struct *wait);
extern int safe_duck_open(struct inode *inode, struct file *filep);
extern int safe_duck_release(struct inode *inode, struct file *file);
extern ssize_t safe_duck_read(struct file *file, char __user *buf, size_t count,
                              loff_t *pos);
extern ssize_t safe_duck_write(struct file *filp, const char __user *buf,
                               size_t count, loff_t *f_pos);
struct _driver_dev_build {
    int major;
    int minor;
    struct cdev cdev;
    dev_t devid;            // device num
    struct class *class;    // class
    struct device *device;  // device
    bool init_chrdev_region;
    bool init_cdev_add;
    bool init_device_create;
    bool init_netfilter;
    bool init_hashmap;
};
extern struct nf_hook_ops g_network_hook_ops;
extern struct file_operations g_fops;
