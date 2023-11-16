#pragma once
#include "../head.h"
struct client_msg_t;
struct kernel_msg_t;
enum class _msg_type;
namespace client_msg {
extern auto call_driver(client_msg_t msg) -> bool;
}  // namespace client_msg

namespace network_event {
auto on_event(_msg_type type, kernel_msg_t msg) -> void;
};
