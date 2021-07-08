#include "perftop.h"

typedef unsigned long long u64;

#define MAX_SYMBOL_LEN 64
#define hashtable_buckets 14

DEFINE_HASHTABLE(kds_hash_table_name, hashtable_buckets);
DEFINE_SPINLOCK(my_lock);

static atomic_t pre_count = ATOMIC_INIT(0);
static atomic_t post_count = ATOMIC_INIT(0);
static atomic_t context_switch_count = ATOMIC_INIT(0);
static char symbol[MAX_SYMBOL_LEN] = "pick_next_task_fair";

struct task_data
{
	struct task_struct * prev;
};
struct kds_hashtable
{
	pid_t pid;
	struct hlist_node hash_node;
	u64 start_tsc;
};
struct kds_red_black
{
	u64 total_tsc;
	pid_t pid;
	struct rb_node node;
};
struct rb_root the_root = RB_ROOT;

// Insert into red black tree the tsc value for a pid 
static void insert_into_red_black(pid_t pid, u64 tsc)
{
	struct kds_red_black * new_red_black;
	struct rb_node *parent, **link;
	struct rb_root * root;
	struct kds_red_black * kds_r_b;
	new_red_black = kmalloc(sizeof(*new_red_black), GFP_ATOMIC);
	new_red_black->total_tsc = tsc;
	new_red_black->pid = pid;
	root = &the_root;
	link = &root->rb_node;
	parent = NULL;
	while (*link)
	{
		parent = *link;
		kds_r_b = rb_entry(parent, struct kds_red_black, node);

		if (kds_r_b->total_tsc > tsc)
		{
			link = &(*link)->rb_right;
		}
		else
		{
			link = &(*link)->rb_left;
		}
	}
	rb_link_node(&new_red_black->node, parent, link);
	rb_insert_color(&new_red_black->node, root);
}

static int entry_pick_next_fair(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct task_data * my_data;
	// if (!current->mm)
	// 	return 1;	/*Skip kernel threads */
	atomic_inc(&pre_count);
	my_data = (struct task_data *) ri->data;
	my_data->prev = (struct task_struct *) regs->si;
	return 0;
}

// Add pid and tsc to hash table
void add_to_hash_table(pid_t pid, u64 tsc)
{
	struct kds_hashtable *new, *curr;
	int bkt;
	new = kmalloc(sizeof(*new), GFP_ATOMIC);
	new->pid = pid;
	new->start_tsc = tsc;
	hash_for_each(kds_hash_table_name, bkt, curr, hash_node)
	{
		if (curr->pid == pid)
		{
			curr->start_tsc = tsc;
			return;
		}
	}
	hash_add(kds_hash_table_name, &new->hash_node, new->pid);
}

// Caclculate elapsed time from hash table with pid 
u64 find_elapsed_time(u64 pid)
{
	struct kds_hashtable * curr;
	int bkt;

	hash_for_each(kds_hash_table_name, bkt, curr, hash_node)
	{
		if (curr->pid == pid)
		{
			return rdtsc() - curr->start_tsc;
		}
	}
	return 0;
}

// Retrive the tsc value from rb tree
static u64 find_rb_total_time(pid_t pid)
{

	struct rb_node * node;
	struct kds_red_black * curr;
	node = rb_first(&the_root);

	while (node)
	{

		curr = rb_entry(node, struct kds_red_black, node);

		if (curr->pid == pid)
		{
			return curr->total_tsc;
		}

		node = rb_next(node);
	}

	return 0;

}

// Remove entro from rb tree
static void remove_from_rb_tree(pid_t pid)
{

	struct rb_node * node;
	struct kds_red_black * curr_node;
	node = rb_first(&the_root);

	while (node)
	{
		curr_node = rb_entry(node, struct kds_red_black, node);
		if (curr_node->pid == pid)
		{
			rb_erase(&curr_node->node, &the_root);
			kfree(curr_node);
			return;
		}
		node = rb_next(node);
	}
}

// Freeing up the rb tree
static void free_red_black_tree(void)
{
	struct rb_node * traversal_node;
	struct kds_red_black * temp_node;
	traversal_node = rb_first(&the_root);

	while (traversal_node)
	{
		temp_node = rb_entry(traversal_node, struct kds_red_black, node);
		rb_erase(&temp_node->node, &the_root);
		kfree(temp_node);
		traversal_node = rb_first(&the_root);
	}
}

// Freeing up the hash table
static void free_hash_table(void)
{
	struct kds_hashtable * temp;
	struct hlist_node * e;
	int bucket;

	hash_for_each_safe(kds_hash_table_name, bucket, e, temp, hash_node)
	{
		hash_del(&temp->hash_node);
		kfree(temp);
	}
}

static int ret_pick_next_fair(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct task_struct * next;
	struct task_data * my_data;
	u64 elapsed_time, rb_time, total_elapsed_time;
	my_data = (struct task_data *) ri->data;
	atomic_inc(&post_count);
	next = (struct task_struct *) regs_return_value(regs);
	if (next != my_data->prev)
	{
		atomic_inc(&context_switch_count);
		//printk("new comm %s and old comm %s", next->comm, my_data->prev->comm);

		spin_lock(&my_lock);

		if (my_data->prev == NULL)
		{
			add_to_hash_table(next->pid, rdtsc());
		}
		else if (next == NULL)
		{
			elapsed_time = find_elapsed_time(my_data->prev->pid);
			rb_time = find_rb_total_time(my_data->prev->pid);
			total_elapsed_time = rb_time + elapsed_time;
			if (total_elapsed_time > 0)
			{
				remove_from_rb_tree(my_data->prev->pid);
				insert_into_red_black(my_data->prev->pid, total_elapsed_time);
			}
		}
		else
		{
			elapsed_time = find_elapsed_time(my_data->prev->pid);
			rb_time = find_rb_total_time(my_data->prev->pid);
			total_elapsed_time = rb_time + elapsed_time;
			if (total_elapsed_time > 0)
			{
				remove_from_rb_tree(my_data->prev->pid);
				insert_into_red_black(my_data->prev->pid, total_elapsed_time);
			}
			add_to_hash_table(next->pid, rdtsc());
		}

		spin_unlock(&my_lock);
	}
	return 0;
}

static struct kretprobe kretprobe_ops = { .handler = ret_pick_next_fair,
	.entry_handler = entry_pick_next_fair,
};

static int kretprobe_counter(struct seq_file *m, void *v)
{
	int i;
	pid_t task_pid;
	u64 tsc;
	struct rb_node * node;
	/*
	Part 1
	seq_printf(m, "Hello World\n");
	seq_printf(m, "Precounter %i\n", atomic_read(&pre_count));
	seq_printf(m, "Postcounter %i\n", atomic_read(&post_count));
	seq_printf(m, "Context switch counter %i\n", atomic_read(&context_switch_count));
	*/
	node = rb_first(&the_root);
	i = 10;
	while (node && i)
	{
		task_pid = rb_entry(node, struct kds_red_black, node)->pid;
		tsc = rb_entry(node, struct kds_red_black, node)->total_tsc;

		seq_printf(m, "Pid %d -> Time (total tsc) : %lld \n", task_pid, tsc);
		node = rb_next(node);
		i--;
	}
	return 0;
}

static int kretprobe_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, kretprobe_counter, NULL);
}

static
const struct proc_ops kretprobe_proc_ops = { .proc_open = kretprobe_proc_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static int __init kretprobe_init(void)
{
	int ret;
	hash_init(kds_hash_table_name);
	proc_create("perftop", 0, NULL, &kretprobe_proc_ops);
	kretprobe_ops.kp.symbol_name = symbol;
	ret = register_kretprobe(&kretprobe_ops);
	if (ret < 0)
	{
		printk(KERN_INFO "register_kretprobe failed, returned %d\n",
			ret);
		return -1;
	}
	printk(KERN_INFO "Planted return probe at %s: %p\n",
		kretprobe_ops.kp.symbol_name, kretprobe_ops.kp.addr);
	return 0;

}

static void __exit kretprobe_exit(void)
{
	unregister_kretprobe(&kretprobe_ops);
	printk(KERN_INFO "kretprobe at %p unregistered\n",
		kretprobe_ops.kp.addr);
	spin_lock(&my_lock);
	free_hash_table();
	free_red_black_tree();
	spin_unlock(&my_lock);
	remove_proc_entry("perftop", NULL);
}

MODULE_LICENSE("GPL");
module_init(kretprobe_init);
module_exit(kretprobe_exit);