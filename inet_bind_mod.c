/*
 * Example kernel module to grant CAP_NET_BIND_SERVICE before making
 * the call to kerne'ls inet_bind(). Allows non-privileged users to biind()
 * to privileged ports < 1024
 *
 * Tested with
 *   -: CentOS kernel-ml-5.6.15
 *   -: gcc (GCC) 9.3.1
 *
 * Live patching has changed in newer kernels
 * kallsyms_lookup_name() and kallsyms_on_each_symbol()
 * are no longer exported
 *
 * https://lwn.net/Articles/813350/
 * https://github.com/torvalds/linux/commit/0bd476e6c67190b5eb7b6e105c8db8ff61103281
 * https://github.com/torvalds/linux/tree/master/samples/livepatch
*/
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/seq_file.h>
#include <linux/kallsyms.h>
#include <linux/ftrace.h>
#include <linux/version.h>
#include <linux/skbuff.h>
#include <linux/types.h>
#include <linux/cred.h>
#include <net/inet_sock.h>
#include <linux/securebits.h>
#include <linux/user_namespace.h>
#include <linux//prctl.h>
#include <linux/security.h>

/* define function name - just to make it easy to use with ftrace (Function Tracer) as a
 * way to "hijack" the kernel inet_bind() function. First we'll call our own inet_bind()
 * function, grant the CAP_NET_BIND_SERVICE capability then, call the real inet_bind() function.
 * The ftrace framework is used in live kernel patching (kpatch)
 * https://www.kernel.org/doc/html/v5.6/trace/ftrace-uses.html
 * https://www.kernel.org/doc/Documentation/trace/ftrace.txt
 * https://www.kernel.org/doc/Documentation/livepatch/livepatch.txt */
#define FTRACE_FUNCTION "inet_bind"
static void *real_inet_bind = NULL;  /* function pointer to real inet_bind() function */

/* module info (prevent `kernel tainted` warning messages when loading the module) */
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");
MODULE_DESCRIPTION("inet_bind() test module");
MODULE_AUTHOR("csh");

/*
 * our patched_function() arguments need to match the kernel's function
 * ./net/ipv4/af_inet.c:int inet_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len) */
int patched_function(struct socket *sock, struct sockaddr *uaddr, int addr_len) {

	/* kernel inet_bind() function, arguments need to match */
	int (*kernel_func)(struct socket *sock, struct sockaddr *uaddr, int addr_len) = (void*)((unsigned long)real_inet_bind + MCOUNT_INSN_SIZE);

	/* socket and permission information for theis task */
	struct sock *sk = sock->sk;
        struct net *net = sock_net(sk);
        const struct cred *creds = current_cred();
        struct cred *task_creds = (struct cred *)__task_cred(current); // is this the same as current_cred() ?

	printk("EXAMPLE: patched_function(): start\n");

	/* task information, `current` is a macro, see: arch/x86/include/asm/current.h */
	printk(KERN_INFO "EXAMPLE: task_name: %s task_pid: %d task_vpid: %d task_tgid: %d\n",
		current->comm, (int)task_pid_nr(current), (int)task_pid_vnr(current), (int)task_tgid_nr(current));

	/* user information
	 * https://www.kernel.org/doc/Documentation/security/credentials.txt */
	printk(KERN_INFO "EXAMPLE: user_uid:%d user_gid:%d user_euid:%d user_egid:%d \n",
		creds->uid.val, creds->gid.val, creds->euid.val, creds->egid.val);

	/* there are a number of ways to change capabilities, task, and user permissions,
	 * here we'll just use the cap_raise() macro */
	if(!ns_capable(net->user_ns, CAP_NET_BIND_SERVICE)) {
		printk(KERN_INFO "EXAMPLE: CAP_NET_BIND_SERVICE, DENIED for this task, Changing permissions ...\n");
		cap_raise(task_creds->cap_effective, CAP_NET_BIND_SERVICE);
	}

	if(ns_capable(net->user_ns, CAP_NET_BIND_SERVICE)) {
		printk(KERN_INFO "EXAMPLE: CAP_NET_BIND_SERVICE - OK\n");
	}

	/* call real kernel inet_bind() fuction after setting CAP_NET_BIND_SERVICE for this task  */
	printk("EXAMPLE: patched_function(): calling real %s()\n",FTRACE_FUNCTION);
	return kernel_func(sock, uaddr, addr_len);
}

static void notrace patch_handler(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *fops, struct pt_regs *regs) {
	regs->ip = (unsigned long)patched_function;
}

static struct ftrace_ops patch_ftrace_ops __read_mostly = {
	.func	= patch_handler,
	.flags	= FTRACE_OPS_FL_SAVE_REGS,
};

static int patch_init(void) {
	int ret;

	ret = ftrace_set_filter_ip(&patch_ftrace_ops, (unsigned long)real_inet_bind, 0, 0);
	if(ret) {
		printk("EXAMPLE: patch_init() error: cannot set ftrace filter\n");
	}

	ret = register_ftrace_function(&patch_ftrace_ops);
	if(ret) {
		printk("EXAMPLE: patch_init() error: cannot set ftrace function\n");
	}

	return(ret);
}

static int kallsyms_walk_callback(void *data, const char *name, struct module *mod, unsigned long addr) {
	if(mod) {
		return 0;
	}

	if(strcmp(name, FTRACE_FUNCTION) == 0) {
		printk(KERN_INFO "EXAMPLE: kallsyms_walk_callback() found: %s @addr: %p\n",FTRACE_FUNCTION,(void *)addr);
		real_inet_bind = (void *)addr;
	}

        return 0;
}

static int __init inet_module_init(void) {
	int rc = 0;

	/* walk /proc/kallsyms for FTRACE_FUNCTION */
	rc = kallsyms_on_each_symbol(kallsyms_walk_callback, NULL);
	if(rc) {
	  	return rc;
	}

	/* if not found, exit with `Bad address` */
	if(real_inet_bind == NULL) {
		printk(KERN_INFO "EXAMPLE: inet_module_init(): - cannot find address for %s\n",FTRACE_FUNCTION);
		return -EFAULT;
	}

	patch_init(); /* add some error checking */
        printk(KERN_INFO "EXAMPLE: init %s() module: OK\n",FTRACE_FUNCTION);
	return rc;
}

static void __exit inet_module_cleanup(void) {
	unregister_ftrace_function(&patch_ftrace_ops);
	real_inet_bind = 0;
	printk(KERN_INFO "EXAMPLE: exit %s() module: OK\n",FTRACE_FUNCTION);
}

module_init(inet_module_init);
module_exit(inet_module_cleanup);

