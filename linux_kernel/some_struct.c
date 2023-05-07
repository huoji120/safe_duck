#include "some_struct.h"

/* define the netfilter hook options */
struct nf_hook_ops g_network_hook_ops = {
    .hook = (nf_hookfn *)network_callback,
    .hooknum = NF_INET_PRE_ROUTING, /* pre-routing hook point */
    .pf = NFPROTO_IPV4,             /* IPv4 protocol family */
    .priority = NF_IP_PRI_FIRST,    /* set highest priority */
};

struct file_operations g_fops = {
    .owner = THIS_MODULE,
    .poll = driver_poll_callback,
    .open = safe_duck_open,
    .release = safe_duck_release,
    .read = safe_duck_read,
};
