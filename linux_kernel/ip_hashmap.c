#include "ip_hashmap.h"
static struct ip_hash_table g_ip_hashtable;

void thread_demon_ip_hashmap(void *ctx) {
    struct hlist_head *head;
    struct hlist_node *node, *tmp;
    struct ip_hashmap_node_t *data;

    while (!kthread_should_stop()) {
        msleep_interruptible(30000);  // 每 30 秒执行一次清理操作
        const s64 current_time_sec = ktime_get_real_seconds();

        spin_lock(&g_ip_hashtable.lock);

        for (int i = 0; i < g_ip_hashtable.bucket_num; ++i) {
            head = &g_ip_hashtable.heads[i];
            hlist_for_each_safe(node, tmp, head) {
                data = container_of(node, struct ip_hashmap_node_t, node);
                if (data) {
                    s64 time_diff =
                        (s64)((s64)data->info.ip_meta_info.remove_time -
                              (s64)data->info.ip_meta_info.last_attack_time);
                    if ((data->info.ip_meta_info.is_attack == false) ||
                        (time_diff <= 0)) {
                        hlist_del(&data->node);
                        kfree(data);
                    }
                }
            }
        }

        spin_unlock(&g_ip_hashtable.lock);
    }

    printk(KERN_INFO "cleanup_iphashmap thread stopped\n");
}
// 初始化哈希表对象
bool init_ip_hashmap(void) {
    struct ip_hash_table *table = &g_ip_hashtable;
    table->bucket_num = BUCKET_NUM;
    table->heads = kzalloc(BUCKET_NUM * sizeof(struct hlist_head), GFP_KERNEL);
    if (table->heads) {
        for (int i = 0; i < BUCKET_NUM; ++i) {
            INIT_HLIST_HEAD(&table->heads[i]);
        }
    }
    spin_lock_init(&table->lock);  // 初始化锁

    // 新建线程，执行清理操作
    table->cleanup_thread = kthread_run((void *)thread_demon_ip_hashmap, NULL,
                                        "thread_demon_ip_hashmap");
    if (IS_ERR(table->cleanup_thread)) {
        printk(KERN_ERR "Failed to create cleanup thread\n");
        return false;
    }
    return true;
}

// 检查是否需要动态调整桶的数量
void check_resize_table(struct ip_hash_table *table) {
    unsigned int bucket_num = table->bucket_num;
    int count = 0;
    for (int i = 0; i < bucket_num; ++i) {
        struct hlist_head *head = &table->heads[i];
        if (!hlist_empty(head)) {
            count++;
        }
    }

    if ((count * 100 / bucket_num) > 70) {
        table->bucket_num = 2 * bucket_num;
        struct hlist_head *new_heads =
            kzalloc(table->bucket_num * sizeof(struct hlist_head), GFP_KERNEL);
        if (new_heads) {
            for (int i = 0; i < table->bucket_num / 2; ++i) {
                struct hlist_node *node, *tmp;
                hlist_for_each_safe(node, tmp, &table->heads[i]) {
                    struct ip_hashmap_node_t *data =
                        container_of(node, struct ip_hashmap_node_t, node);
                    hlist_del(&data->node);
                    int idx =
                        hash_32(data->info.ip_address_key, table->bucket_num);
                    hlist_add_head(&data->node, &new_heads[idx]);
                }
            }

            kfree(table->heads);
            table->heads = new_heads;
        }
    }
}

// 获取并插入哈希表节点
void put_ipdata_by_hashmap(size_t ip_address_key,
                           struct ip_hashmap_info *info) {
    struct ip_hash_table *table = &g_ip_hashtable;
    int idx = hash_32(ip_address_key, table->bucket_num);
    // 新建哈希表节点
    struct ip_hashmap_node_t *data =
        kmalloc(sizeof(struct ip_hashmap_node_t), GFP_KERNEL);
    if (data) {
        memcpy(&data->info, info, sizeof(struct ip_hashmap_info));
        spin_lock(&table->lock);
        hlist_add_head(&data->node, &table->heads[idx]);
        check_resize_table(table);
        spin_unlock(&table->lock);
    }
}

// 通过关键字获取哈希表节点
struct ip_hashmap_node_t *get_ipdata_by_hashmap(size_t ip_address_key) {
    struct ip_hash_table *table = &g_ip_hashtable;
    spin_lock(&table->lock);

    int idx = hash_32(ip_address_key, table->bucket_num);
    struct hlist_head *head = &table->heads[idx];
    struct hlist_node *node = head->first;
    while (node) {
        struct ip_hashmap_node_t *data =
            container_of(node, struct ip_hashmap_node_t, node);
        if (ip_address_key == data->info.ip_address_key) {
            spin_unlock(&table->lock);
            return data;
        }
        node = node->next;
    }
    spin_unlock(&table->lock);
    return NULL;
}

// 从哈希表中删除节点
void del_ipdata_by_hashmap(size_t ip_address_key) {
    struct ip_hash_table *table = &g_ip_hashtable;
    spin_lock(&table->lock);

    int idx = hash_32(ip_address_key, table->bucket_num);
    struct hlist_head *head = &table->heads[idx];
    struct hlist_node *node = head->first;
    while (node) {
        struct ip_hashmap_node_t *data =
            container_of(node, struct ip_hashmap_node_t, node);
        if (ip_address_key == data->info.ip_address_key) {
            hlist_del(&data->node);
            kfree(data);
            break;
        }
        node = node->next;
    }
    // 检查是否需要调整桶的数量
    check_resize_table(table);
    spin_unlock(&table->lock);
}
void cleanup_iphashmap(void) {
    kthread_stop(g_ip_hashtable.cleanup_thread);  // 停止清理线程
    if (g_ip_hashtable.heads) {
        spin_lock(&g_ip_hashtable.lock);
        struct hlist_head *head, *tmp;
        struct hlist_node *node;
        struct ip_hashmap_node_t *data;
        // 释放哈希表节点动态分配的内存
        for (int i = 0; i < g_ip_hashtable.bucket_num; ++i) {
            head = &g_ip_hashtable.heads[i];
            hlist_for_each_entry_safe(data, node, head, node) {
                hlist_del(&data->node);
                kfree(data);
            }
        }
        kfree(g_ip_hashtable.heads);
        spin_unlock(&g_ip_hashtable.lock);
    }

    printk(KERN_INFO "clean up iphashmap\n");
}
