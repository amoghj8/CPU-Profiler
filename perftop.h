#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/threads.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/rbtree.h>
#include <linux/hashtable.h>

static int __init kretprobe_init(void);

static void __exit kretprobe_exit(void);

static int kretprobe_proc_open(struct inode *inode, struct file *file);

static int kretprobe_counter(struct seq_file *m, void *v);

static int ret_pick_next_fair(struct kretprobe_instance *ri, struct pt_regs *regs);

static int entry_pick_next_fair(struct kretprobe_instance *ri, struct pt_regs *regs);

static void insert_into_red_black(pid_t pid, u64 tsc);

static int entry_pick_next_fair(struct kretprobe_instance *ri, struct pt_regs *regs);

void add_to_hash_table(pid_t pid, u64 tsc);

u64 find_elapsed_time(u64 pid);

static u64 find_rb_total_time(pid_t pid);

static void remove_from_rb_tree(pid_t pid);

static void free_red_black_tree(void);

static void free_hash_table(void);