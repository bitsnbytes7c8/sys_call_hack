#include<linux/kernel.h>
#include<linux/module.h>
#include <linux/moduleparam.h>	/* which will have params */
#include <linux/unistd.h>	/* The list of system calls */

/* 
 * For the current (process) structure, we need
 * this to know who the current user is. 
 */
#include <linux/sched.h>
#include <asm/uaccess.h>
#include <linux/cred.h>
#include<linux/syscalls.h>
#include<linux/namei.h>
#include<linux/init.h>
#include<asm/cacheflush.h>

/* 
 * The system call table (a table of functions). We
 * just define this as external, and the kernel will
 * fill it up for us when we are insmod'ed
 *
 * sys_call_table is no longer exported in 2.6.x kernels.
 * If you really want to try this DANGEROUS module you will
 * have to apply the supplied patch against your current kernel
 * and recompile it.
 */
unsigned long *sys_call_table;
/* 
 * UID we want to spy on - will be filled from the
 * command line 
 */
static int uid;
module_param(uid, int, 0644);

void (*pages_rw)(struct page *page, int numpages) =  (void *) 0xc102abe0;
void (*pages_ro)(struct page *page, int numpages) =  (void *) 0xc102aeb0;

/* 
 * A pointer to the original system call. The reason
 * we keep this, rather than call the original function
 * (sys_open), is because somebody else might have
 * replaced the system call before us. Note that this
 * is not 100% safe, because if another module
 * replaced sys_open before us, then when we're inserted
 * we'll call the function in that module - and it
 * might be removed before we are.
 *
 * Another reason for this is that we can't get sys_open.
 * It's a static variable, so it is not exported. 
 */
asmlinkage int (*original_call) (const char *, int, int);

/* 
 * The function we'll replace sys_open (the function
 * called when you call the open system call) with. To
 * find the exact prototype, with the number and type
 * of arguments, we find the original function first
 * (it's at fs/open.c).
 *
 * In theory, this means that we're tied to the
 * current version of the kernel. In practice, the
 * system calls almost never change (it would wreck havoc
 * and require programs to be recompiled, since the system
 * calls are the interface between the kernel and the
 * processes).
 */
asmlinkage int our_sys_open(const char *filename, int flags, int mode)
{
	int i = 0;
	char ch;

	/* 
	 * Check if this is the user we're spying on 
	 */
	/* 
	 * Report the file, if relevant 
	 */
	if(uid == get_current_user()->uid)
	{
		printk("Opened file by\n");
		do {
			get_user(ch, filename + i);
			i++;
			printk("%c", ch);
		} while (ch != 0);
		printk("\n");
	}

	/* 
	 * Call the original sys_open - otherwise, we lose
	 * the ability to open files 
	 */
	return original_call(filename, flags, mode);
}

/*int set_page_rw(long unsigned int _addr)
{
  EXPORT_SYMBOL_NOVERS(_addr);
  return set_memory_rw(PAGE_ALIGN(_addr) - PAGE_SIZE, 1);
}*/


/* 
 * Initialize the module - replace the system call 
 */
int init_module()
{
	/* 
	 * Warning - too late for it now, but maybe for
	 * next time... 
	 */
	printk(KERN_ALERT "I'm dangerous. I hope you did a ");
	printk(KERN_ALERT "sync before you insmod'ed me.\n");
	printk(KERN_ALERT "My counterpart, cleanup_module(), is even");
	printk(KERN_ALERT "more dangerous. If\n");
	printk(KERN_ALERT "you value your file system, it will ");
	printk(KERN_ALERT "be \"sync; rmmod\" \n");
	printk(KERN_ALERT "when you remove this module.\n");

	/*int i=MAX_TRY;
        unsigned long *sys_table = (unsigned long *)&system_utsname;

        while(i)
        {
                if(sys_table[__NR_read] == (unsigned long)sys_read)
                {
                        sys_call_table=sys_table;
                        flag=1;
                        break;   
                }
                i--;
                sys_table++;
                
        }*/
	write_cr0 (read_cr0 () & (~ 0x10000)); // Change the protected bit of Control Register
	sys_call_table = (long unsigned int*) 0xc1576160;
	struct page *sys_call_table_temp = virt_to_page(&sys_call_table[__NR_open]);
	pages_rw(sys_call_table_temp, 1);
	/* 
	 * Keep a pointer to the original function in
	 * original_call, and then replace the system call
	 * in the system call table with our_sys_open 
	 */
	original_call = sys_call_table[__NR_open];
	//set_page_rw(sys_call_table);
	sys_call_table[__NR_open] = our_sys_open;

	/* 
	 * To get the address of the function for system
	 * call foo, go to sys_call_table[__NR_foo]. 
	 */

	printk(KERN_INFO "Spying on UID:%d\n", uid);

	return 0;
}

/* 
 * Cleanup - unregister the appropriate file from /proc 
 */
void cleanup_module()
{
	/* 
	 * Return the system call back to normal 
	 */
	if (sys_call_table[__NR_open] != our_sys_open) {
		printk(KERN_ALERT "Somebody else also played with the ");
		printk(KERN_ALERT "open system call\n");
		printk(KERN_ALERT "The system may be left in ");
		printk(KERN_ALERT "an unstable state.\n");
	}
	write_cr0 (read_cr0 () & (~ 0x10000)); // Change back the protected bit of control register
	struct page *sys_call_table_temp = virt_to_page(&sys_call_table[__NR_open]);
	sys_call_table[__NR_open] = original_call;
	pages_ro(sys_call_table_temp, 1);
	printk(KERN_INFO "Module exit\n");
}

