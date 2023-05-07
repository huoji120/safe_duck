#include "tools.h"
namespace tools {
auto cover_ip(unsigned int ip) -> std::string {
    std::string ip_str;
    ip_str = std::to_string(ip & 0xff) + "." +
             std::to_string((ip >> 8) & 0xff) + "." +
             std::to_string((ip >> 16) & 0xff) + "." +
             std::to_string((ip >> 24) & 0xff);
    return ip_str;
}
}  // namespace tools
