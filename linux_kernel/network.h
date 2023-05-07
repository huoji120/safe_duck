#pragma once
#include "head.h"
#define IP_ATTCK_BLOCK_TIME 600
#define SYN_SCAN_THRESHOLD 500
#define SYN_SCAN_TIME 10
#define SSH_BRUTE_FORCE_THRESHOLD 10
#define SSH_BRUTE_FORCE_TIME 5
#define SSH_PORT 22
extern unsigned int network_callback(const struct nf_hook_ops *ops,
                                     struct sk_buff *skb,
                                     const struct net_device *in,
                                     const struct net_device *out,
                                     int (*okfn)(struct sk_buff *));
extern void block_ip_address(size_t ip_address, size_t time_sec);
extern bool check_is_blacklist_ip(size_t ip_address);
