#include "hook.h"
#include <linux/sched/signal.h>
#include <linux/kprobes.h>
#include <linux/unistd.h>
#include <linux/fs.h>

#define MAX_PATH_LEN 256
#define MAX_ARGS_LEN 4096

static struct kprobe kp = {
    .symbol_name = "do_execveat_common.isra.0",
};

static int handler_pre(struct kprobe *p, struct pt_regs *regs) {
    struct task_struct *task = current;
    struct task_struct *parent = task->parent;
    struct mm_struct *mm = task->mm;
    struct file *file;
    char *pathname;
    char *args_buf;

    if (mm) {
        file = mm->exe_file;
        if (file) {
            pathname = kmalloc(PATH_MAX, GFP_KERNEL);
            if (pathname) {
                printk(KERN_INFO "Program Path: %s\n",
                       d_path(&file->f_path, pathname, PATH_MAX));
            }
        }
    }
    args_buf = kmalloc(MAX_ARGS_LEN, GFP_KERNEL);
    if (args_buf) {
        if (copy_from_user(args_buf, (const void __user *)regs->di,
                           MAX_ARGS_LEN) == 0) {
            args_buf[MAX_ARGS_LEN - 1] = '\0';
        }
        // kfree(args_buf);
    }
    printk(KERN_INFO "PID: %d\n", task->pid);
    printk(KERN_INFO "PPID: %d\n", parent->pid);
    printk(KERN_INFO "Program Name: %s\n", task->comm);
    printk(KERN_INFO "Program Args: %s\n", args_buf);
    if (args_buf) {
        kfree(args_buf);
    }
    if (pathname) {
        kfree(pathname);
    }
    return 0;
}
bool init_hooks(void) {
    int ret;

    ret = register_kprobe(&kp);
    if (ret < 0) {
        printk(KERN_ERR "register_kprobe failed, returned %d\n", ret);
        return false;
    }
    kp.pre_handler = handler_pre;

    printk(KERN_ERR "Planted kprobe at %p\n", kp.addr);
    return true;
}
void uninstall_hooks(void) { unregister_kprobe(&kp); }
