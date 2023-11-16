#include "head.h"

auto main() -> int {
    global::ip_blacklist_db = new IpBlacklistDB("ip_blacklist.db");
    global::ip_blacklist_db->createTable();

    if (client_msg::init()) {
        client_msg::dispath_kernel_msg();
    }
    return 0;
}
