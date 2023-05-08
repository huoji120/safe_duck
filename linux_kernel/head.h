#pragma once

#include <linux/init.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/time.h>
#include <linux/jiffies.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/net.h>
#include <linux/errno.h>
#include <linux/spinlock.h>
#include <linux/cdev.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/hash.h>
#include <linux/kprobes.h>

#include "some_struct.h"
#include "global.h"
#include "msg.h"
#include "ip_hashmap.h"
#include "network.h"
#include "client_msg.h"
#include "my_kallsyms_lookup_name.h"
#include "hook.h"
#define DEVICE_NAME "safe_duck"
#define DEVICE_CNT 1
MODULE_LICENSE("GPL");
MODULE_AUTHOR("huoji");
