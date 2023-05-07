#pragma once
#include "head.h"
#define BUCKET_NUM 1000  // 初始桶的数量
struct ip_hash_table {
    struct hlist_head *heads;  // 存放桶的指针数组
    unsigned int bucket_num;   // 当前桶的数量
    spinlock_t lock;           // 锁，确保同步和互斥访问哈希表
    struct task_struct *cleanup_thread;  // 执行清理操作的线程
};
// 定义哈希表节点
struct syn_scan_info_t {
    size_t last_seen;
    size_t num_syn_packets;
};

struct crack_ip_info_t {
    size_t last_seen;
    size_t num_connect;
};
struct ip_meta_info_t {
    bool is_attack;
    size_t last_attack_time;
    size_t remove_time;
};
struct ip_hashmap_info {
    size_t ip_address_key;
    struct syn_scan_info_t syn_scan_info;
    struct crack_ip_info_t crack_ip_info;
    struct ip_meta_info_t ip_meta_info;
};
struct ip_hashmap_node_t {
    struct hlist_node node;  // 哈希表链表节点
    struct ip_hashmap_info info;
};
extern bool init_ip_hashmap(void);
extern void check_resize_table(struct ip_hash_table *table);
extern void put_ipdata_by_hashmap(size_t ip_address_key,
                                  struct ip_hashmap_info *info);
extern struct ip_hashmap_node_t *get_ipdata_by_hashmap(size_t ip_address_key);
extern void del_ipdata_by_hashmap(size_t ip_address_key);
extern void cleanup_iphashmap(void);
