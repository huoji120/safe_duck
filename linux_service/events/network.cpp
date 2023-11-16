#include "network.h"
#include <unordered_map>
#include <shared_mutex>
#include <ctime>
#include <mutex>
namespace network_event {
// read write lock
std::shared_mutex ip_blacklist_lock;
std::unordered_map<uint32_t, std::time_t> ip_blacklist_cache;
auto block_ip(uint32_t ip_address, size_t time_sec) -> bool {
    client_msg_t msg{0};
    msg.check_sum = MSG_CHECK_SUM;
    msg.type = static_cast<int>(_msg_type::SD_MSG_TYPE_CLIENT_BLOCK_IP);
    msg.u.ip_address.src_ip = ip_address;
    msg.u.ip_address.block_time = time_sec;
    return client_msg::call_driver(msg);
}
auto unblock_ip(uint32_t ip_address) -> bool {
    client_msg_t msg{0};
    msg.check_sum = MSG_CHECK_SUM;
    msg.type = static_cast<int>(_msg_type::SD_MSG_TYPE_CLIENT_UNBLOCK_IP);
    msg.u.ip_address.src_ip = ip_address;
    return client_msg::call_driver(msg);
}
auto on_ip_connect(uint32_t ip_address) -> bool {
    std::shared_lock lock(ip_blacklist_lock);
    if (ip_blacklist_cache.find(ip_address) != ip_blacklist_cache.end()) {
        const auto current_time = std::time(nullptr);
        const auto block_time = ip_blacklist_cache[ip_address];
        if (current_time - block_time < MAX_BLOCK_TIME) {
            LOG("IP %s is in cache block list\n",
                tools::cover_ip(ip_address).c_str());
            return true;
        }
        // cover lock to write lock, remove the ip from cache
        lock.unlock();
        std::unique_lock ulock(ip_blacklist_lock);
        ip_blacklist_cache.erase(ip_address);
    }
    const auto is_still_in_block_list =
        global::ip_blacklist_db->selectRecordByIpAndTime(ip_address,
                                                         MAX_BLOCK_TIME);
    if (is_still_in_block_list) {
        const auto block_time = is_still_in_block_list.value().time;
        if (block_time != 0) {
            lock.unlock();
            std::unique_lock ulock(ip_blacklist_lock);
            ip_blacklist_cache[ip_address] =
                is_still_in_block_list.value().time;
        }

        LOG("IP %s is still in block list\n",
            tools::cover_ip(ip_address).c_str());
        return true;
    }
    return false;
}

auto on_event(_msg_type type, kernel_msg_t msg) -> void {
    auto ip_address = msg.u.ip_action.src_ip;
    auto ip_str = tools::cover_ip(ip_address);
    auto reason = std::string("");
    bool is_block_ip = false;

    switch (type) {
        case _msg_type::SD_MSG_TYPE_NEW_IP_CONNECT: {
            LOG("New IP connection: %s\n", ip_str.c_str());
            is_block_ip = on_ip_connect(ip_address);
        } break;
        case _msg_type::SD_MSG_TYPE_SYN_ATTACK: {
            LOG("Block ip for syn attack: %s \n", ip_str.c_str());
            is_block_ip = true;
            reason = "Syn attack detected";
        } break;
        case _msg_type::SD_MSG_TYPE_SSH_BF_ATTACK: {
            LOG("Block ip for SSH brute force attack: %s \n", ip_str.c_str());
            is_block_ip = true;
            reason = "SSH brute force attack detected";
        } break;
        default:
            LOG("Unknown message type: %d\n", msg.type);
            break;
    }
    if (is_block_ip) {
        block_ip(msg.u.ip_action.src_ip, MAX_BLOCK_TIME);
        if (reason.size() > 1) {
            global::ip_blacklist_db->insertRecord(ip_address, reason,
                                                  std::time(nullptr));
        }
    }
}
};  // namespace network_event
