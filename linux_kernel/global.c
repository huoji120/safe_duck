#include "head.h"
struct _driver_dev_build g_driver_dev_build;
bool g_is_r3_ready = false;
DECLARE_WAIT_QUEUE_HEAD(g_r3_wait_queue);
