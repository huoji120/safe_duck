#include "my_kallsyms_lookup_name.h"
unsigned long (*g_kallsyms_lookup_name_fun)(const char *name) = NULL;

int kallsyms_lookup_name_pre(struct kprobe *p, struct pt_regs *regs) {
    return 0;
}
static struct kprobe kp_kallsyms_lookup_name = {
    .symbol_name = "kallsyms_lookup_name",
};

// 调用kprobe找到kallsyms_lookup_name的地址位置
int init_kallsyms_lookup_name_i(void) {
    int ret = -1;
    kp_kallsyms_lookup_name.pre_handler = kallsyms_lookup_name_pre;
    ret = register_kprobe(&kp_kallsyms_lookup_name);
    if (ret < 0) {
        printk(KERN_INFO "register_kprobe failed, error:%d\n", ret);
        return ret;
    }
    printk(KERN_INFO "kallsyms_lookup_name addr: %p\n",
           kp_kallsyms_lookup_name.addr);
    g_kallsyms_lookup_name_fun = (void *)kp_kallsyms_lookup_name.addr;
    unregister_kprobe(&kp_kallsyms_lookup_name);
    return ret;
}

bool init_kallsyms_lookup_name(void) {
    init_kallsyms_lookup_name_i();
    return g_kallsyms_lookup_name_fun != NULL;
}
