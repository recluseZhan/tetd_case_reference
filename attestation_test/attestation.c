#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <asm/io.h>

MODULE_LICENSE("GPL");

static int __init attestation_init(void){
    unsigned long *va = kmalloc(4096,GFP_KERNEL);
    unsigned long pa = virt_to_phys(va);
    memset(va,1,4096);
    unsigned long ret=1;
    asm volatile(
        "mov $2,%%rax\n\t"
        "mov %1,%%rcx\n\t"
        "mov $2,%%rdx\n\t"
        "tdcall\n\t"
        "mov %%rax,%0\n\t"
        :"=r"(ret):"r"(pa):
    );
    printk("ret=%lx\n",ret);

    unsigned long *report_va = kmalloc(4096,GFP_KERNEL);
    unsigned long report_pa = virt_to_phys(report_va);
    memset(report_va,0,4096);
    asm volatile(
        "mov $4,%%rax\n\t"
	"mov %1,%%rcx\n\t"
	"mov %2,%%rdx\n\t"
	"mov $0,%%r8\n\t"
	"tdcall\n\t"
	"mov %%rax,%0\n\t"
	:"=r"(ret):"r"(report_pa),"r"(pa):
    );
    printk("ret2=%lx\n",ret);
    
    printk(KERN_INFO "loading attestation\n");
    return 0;
}
static void __exit attestation_exit(void){
    printk(KERN_INFO "unloading attestation\n");
}
module_init(attestation_init);
module_exit(attestation_exit);
