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
#include "some_struct.h"
#include "global.h"
#include "msg.h"
#define DEVICE_NAME "safe_duck"
#define DEVICE_CNT 1
MODULE_LICENSE("GPL");
MODULE_AUTHOR("huoji");
