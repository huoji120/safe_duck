#include "head.h"

auto main() -> int {
    if (client_msg::init()) {
        client_msg::dispath_kernel_msg();
    }
    return 0;
}
