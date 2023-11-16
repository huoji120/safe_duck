#include "network.h"

void block_ip_address(u32 ip_address, size_t time_sec) {
    struct ip_hashmap_node_t *data = get_ipdata_by_hashmap(ip_address);
    const s64 current_time_sec = ktime_get_real_seconds();

    if (data == NULL) {
        struct ip_hashmap_info info;
        info.ip_address_key = ip_address;
        info.ip_meta_info.last_attack_time = current_time_sec;
        info.ip_meta_info.remove_time = current_time_sec + time_sec;
        info.ip_meta_info.is_attack = true;
        put_ipdata_by_hashmap(ip_address, &info);
        return;
    }
    data->info.ip_meta_info.last_attack_time = current_time_sec;
    data->info.ip_meta_info.remove_time = current_time_sec + time_sec;
    data->info.ip_meta_info.is_attack = true;
}
bool check_is_blacklist_ip(u32 ip_address) {
    struct ip_hashmap_node_t *data = get_ipdata_by_hashmap(ip_address);
    if (data == NULL) {
        return false;
    }
    return data->info.ip_meta_info.is_attack;
}
bool check_syn_attack(struct iphdr *ip_header, struct sk_buff *skb) {
    bool is_block = false;
    do {
        if (ip_header->protocol != IPPROTO_TCP) {
            break;
        }
        struct tcphdr *tcp_header = tcp_hdr(skb);
        if (tcp_header == NULL) {
            break;
        }
        if (tcp_header->syn == 0 || tcp_header->ack || tcp_header->rst) {
            break;
        }
        u32 ip_address_key = ip_header->saddr;
        struct ip_hashmap_node_t *data = get_ipdata_by_hashmap(ip_address_key);
        const s64 current_time_sec = ktime_get_real_seconds();
        if (data == NULL) {
            struct ip_hashmap_info info;
            info.ip_address_key = ip_address_key;
            info.syn_scan_info.last_seen = current_time_sec;
            info.syn_scan_info.num_syn_packets = 1;
            put_ipdata_by_hashmap(ip_address_key, &info);
            break;
        }
        s64 time_diff = current_time_sec - data->info.syn_scan_info.last_seen;
        if (time_diff >= SYN_SCAN_TIME) {
            data->info.syn_scan_info.num_syn_packets = 0;
            data->info.syn_scan_info.last_seen = current_time_sec;
            break;
        }
        data->info.syn_scan_info.num_syn_packets++;
        if (data->info.syn_scan_info.num_syn_packets >= SYN_SCAN_THRESHOLD) {
            // printk(KERN_ERR "SYN attack detected from %pI4 num packet: %d
            // \n",
            //        &ip_header->saddr,
            //        data->info.syn_scan_info.num_syn_packets);
            push_msg_syn_attack(ip_address_key);
            block_ip_address(ip_address_key, IP_ATTCK_BLOCK_TIME);
            is_block = true;
        }

    } while (false);
    return is_block;
}

bool check_ssh_brute_force_attack(struct iphdr *ip_header,
                                  struct sk_buff *skb) {
    bool is_block = false;
    do {
        if (ip_header->protocol != IPPROTO_TCP) {
            break;
        }
        struct tcphdr *tcp_header = tcp_hdr(skb);
        if (tcp_header == NULL) {
            break;
        }
        if ((tcp_header->syn == 1) && (tcp_header->ack == 0)) {
            break;
        }
        // check port
        if (ntohs(tcp_header->dest) != SSH_PORT) {
            break;
        }
        u32 ip_address_key = ip_header->saddr;
        struct ip_hashmap_node_t *data = get_ipdata_by_hashmap(ip_address_key);
        const s64 current_time_sec = ktime_get_real_seconds();
        if (data == NULL) {
            struct ip_hashmap_info info;
            info.ip_address_key = ip_address_key;
            info.crack_ip_info.last_seen = current_time_sec;
            info.crack_ip_info.num_connect = 1;
            put_ipdata_by_hashmap(ip_address_key, &info);
            break;
        }
        s64 time_diff = current_time_sec - data->info.crack_ip_info.last_seen;
        if (time_diff >= SSH_BRUTE_FORCE_TIME) {
            data->info.crack_ip_info.num_connect = 0;
            data->info.crack_ip_info.last_seen = current_time_sec;
            break;
        }
        data->info.crack_ip_info.num_connect++;
        if (data->info.crack_ip_info.num_connect >= SSH_BRUTE_FORCE_THRESHOLD) {
            // printk(KERN_ERR "SYN attack detected from %pI4 num packet: %d
            // \n",
            //        &ip_header->saddr,
            //        data->info.syn_scan_info.num_syn_packets);
            push_msg_ssh_bf_attack(ip_address_key);
            block_ip_address(ip_address_key, IP_ATTCK_BLOCK_TIME);
            is_block = true;
        }

    } while (false);
    return is_block;
}
bool check_in_packet(struct iphdr *ip_header, struct sk_buff *skb) {
    bool is_block = false;
    do {
        // 127.0.0.1
        if (ip_header->saddr == 0 || ip_header->saddr == 0x0100007F) {
            break;
        }
        if (check_is_blacklist_ip(ip_header->saddr)) {
            is_block = true;
            printk(KERN_ERR "Block ip address: %pI4\n", &ip_header->saddr);
            break;
        }
        if (check_syn_attack(ip_header, skb)) {
            is_block = true;
            break;
        }
        if (check_ssh_brute_force_attack(ip_header, skb)) {
            is_block = true;
            break;
        }
        struct tcphdr *tcp_header = tcp_hdr(skb);
        if (tcp_header == NULL) {
            break;
        }
        if ((tcp_header->syn == 1) && (tcp_header->ack == 0)) {
            // push ip address to list
            push_msg_new_ip_connect(ip_header->saddr);
        }
    } while (false);

    return is_block;
}
unsigned int network_callback(const struct nf_hook_ops *ops,
                              struct sk_buff *skb, const struct net_device *in,
                              const struct net_device *out,
                              int (*okfn)(struct sk_buff *)) {
    bool is_block = false;
    do {
        if (skb == NULL) {
            break;
        }
        struct iphdr *ip_header = ip_hdr(skb);
        if (ip_header == NULL) {
            break;
        }
        if (ip_header->saddr == ip_header->daddr) {
            // 本机连接本机的数据包
            break;
        }
        if (skb->pkt_type == PACKET_HOST) {
            // 这是一个输入数据包
            is_block = check_in_packet(ip_header, skb);
        }
    } while (false);

    return is_block ? NF_DROP : NF_ACCEPT;
}
