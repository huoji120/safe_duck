#include "network.h"
namespace network_event {

auto block_ip(uint32_t ip_address, size_t time_sec) -> bool {
    client_msg_t msg{0};
    msg.check_sum = MSG_CHECK_SUM;
    msg.type = static_cast<int>(_msg_type::SD_MSG_TYPE_CLIENT_BLOCK_IP);
    msg.u.ip_address.src_ip = ip_address;
    msg.u.ip_address.block_time = time_sec;
    return client_msg::call_driver(msg);
}
auto on_ip_connect(uint32_t ip_address) -> bool {
    const auto is_still_in_block_list =
        global::ip_blacklist_db->selectRecordByIpAndTime(ip_address,
                                                         MAX_BLOCK_TIME);
    if (is_still_in_block_list) {
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
