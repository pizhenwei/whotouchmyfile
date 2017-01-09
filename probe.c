#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <asm/uaccess.h>

static struct kprobe kp = {
	.symbol_name    = "vfs_write",
};

static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct file *file = (struct file *)regs->di;
	char *buf = NULL;
	size_t size = 0;
	//printk(KERN_INFO "pre_handler: p->addr = 0x%p, ip = %lx," " flags = 0x%lx\n", p->addr, regs->ip, regs->flags);

#if 0
	if (file->f_dentry && file->f_dentry->d_name.name)
		printk(KERN_INFO "name = %s" , file->f_dentry->d_name.name);
#endif

	if (strncmp(file->f_dentry->d_name.name, "config", 4) == 0)
		printk(KERN_INFO "bingo" , file->f_dentry->d_name.name);
	else
		return 0;

	size = regs->dx + 1;
	printk(KERN_INFO "process = %s , pid = %ld, file = %s, size = %ld\n" , current->comm, current->pid, file->f_dentry->d_name.name, size);

	buf = (char*)kmalloc(size, 0);
	if (buf == NULL)
		return 0;

	memset(buf, 0x00, size);
	copy_from_user(buf, regs->si, size);
	printk(KERN_INFO "%s" , buf);
	kfree(buf);

	return 0;
}

static void handler_post(struct kprobe *p, struct pt_regs *regs,
		unsigned long flags)
{
	//printk(KERN_INFO "post_handler: p->addr = 0x%p, flags = 0x%lx\n", p->addr, regs->flags);
}

static int handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
	printk(KERN_INFO "fault_handler: p->addr = 0x%p, trap #%dn",
			p->addr, trapnr);
	return 0;
}

static int __init kprobe_init(void)
{
	int ret;
	kp.pre_handler = handler_pre;
	kp.post_handler = handler_post;
	kp.fault_handler = handler_fault;

	ret = register_kprobe(&kp);
	if (ret < 0) {
		printk(KERN_INFO "register_kprobe failed, returned %d\n", ret);
		return ret;
	}
	printk(KERN_INFO "Planted kprobe at %p\n", kp.addr);
	return 0;
}

static void __exit kprobe_exit(void)
{
	unregister_kprobe(&kp);
	printk(KERN_INFO "kprobe at %p unregistered\n", kp.addr);
}

module_init(kprobe_init)
module_exit(kprobe_exit)
MODULE_LICENSE("GPL");
MODULE_AUTHOR("PiZhenwei p_ace@126.com");