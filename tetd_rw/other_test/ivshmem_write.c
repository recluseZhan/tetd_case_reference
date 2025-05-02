#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/pci.h>

#define IVSHMEM_BAR0_ADDRESS 0x383800000000
#define IVSHMEM_BAR0_SIZE (1 * 1024 * 1024)

void __iomem *ivshmem_base;  
struct task_struct *get_task(pid_t pid) {
    struct pid *pid_struct = find_get_pid(pid); 
    if (!pid_struct) {
        return NULL; 
    }
    struct task_struct *task = pid_task(pid_struct, PIDTYPE_PID); 
    return task;
}
static int copy_pcb(void){
   struct task_struct *task;
   //task = current;
   task = get_task(2);
   printk("task:0x%lx, task_size=0x%lx",task,sizeof(struct task_struct));
   memcpy(ivshmem_base, task, sizeof(struct task_struct));
   return 0;
}

static int copy_idt(void){
    struct desc_ptr idt_desc;
    unsigned long idt_base;
    size_t idt_size = sizeof(struct desc_struct) * (IDT_ENTRIES);

    // Get the base address of the IDT.
    asm volatile("sidt %0" : "=m"(idt_desc));
    idt_base = idt_desc.address;
    
    printk("idt:0x%lx, idt_size:0x%lx",idt_base,idt_size);
    memcpy(ivshmem_base, (void *)idt_base, idt_size);

    printk(KERN_INFO "Copied IDT to physical address 0x%lx\n", IVSHMEM_BAR0_ADDRESS);
    return 0; 
}

static int copy_gdt(void){
    struct desc_ptr gdt_desc;
    asm("sgdt %0" : "=m"(gdt_desc));
    
    memcpy(ivshmem_base, (void *)gdt_desc.address, gdt_desc.size);
    printk("gdt %lx, limit %lx ",gdt_desc.address, gdt_desc.size);

    return 0;
}

void read_pcb(void){
    unsigned long value;
    for(int i = 0; i < sizeof(struct task_struct)/8; i++){
        value = readq(ivshmem_base + i * 8);
        pr_info(KERN_CONT "0x%x ", value);
    }
}

void read_idt(void){
    unsigned long value;
    for(int i = 0; i < 256; i++){
        value = readq(ivshmem_base + i * 8);
	pr_info("Read value 0x%x from offset 0x%x\n", value, i*8);
    }
}

void read_gdt(void){
    unsigned long value;
    for (int i = 0; i < 0x7f / sizeof(unsigned long); i++) {
        value = readq(ivshmem_base + i * 8);
        printk(KERN_CONT "0x%lx ", value);
    }
}

static void write_ivshmem(int offset, uint32_t value) {
    if (offset < IVSHMEM_BAR0_SIZE) {
        writel(value, ivshmem_base + offset);  // Writes the value at the specified offset.
        pr_info("Wrote value 0x%x to offset 0x%x\n", value, offset);
    } else {
        pr_err("Offset out of bounds: 0x%x\n", offset);
    }
}

static uint32_t read_ivshmem(int offset) {
    uint32_t value;

    if (offset < IVSHMEM_BAR0_SIZE) {
        value = readl(ivshmem_base + offset);  // Reads a value from the specified offset.
        pr_info("Read value 0x%x from offset 0x%x\n", value, offset);
        return value;
    } else {
        pr_err("Offset out of bounds: 0x%x\n", offset);
        return 0;
    }
}

static int __init ivshmem_init(void) {
    uint32_t read_value;

    pr_info("Initializing ivshmem module...\n");

    // Map the BAR 0 memory region of ivshmem.
    ivshmem_base = ioremap(IVSHMEM_BAR0_ADDRESS, IVSHMEM_BAR0_SIZE);
    if (!ivshmem_base) {
        pr_err("Could not map ivshmem memory\n");
        return -EIO;
    }

    pr_info("ivshmem memory mapped at address: %p\n", ivshmem_base);

    //write_ivshmem(0, 0x12345678);  // Write 0x12345678 to offset 0.
    //copy_idt();
    //read_idt();
    //copy_pcb();
    //read_pcb();
    copy_gdt();  
    read_gdt();
    //mb();

    //read_value = read_ivshmem(0);
    //pr_info("Read value 0x%x from offset 0x0\n", read_value);

    return 0;
}

static void __exit ivshmem_exit(void) {
    if (ivshmem_base) {
        iounmap(ivshmem_base);
        pr_info("ivshmem memory unmapped\n");
    }

    pr_info("Exiting ivshmem module\n");
}


module_init(ivshmem_init);
module_exit(ivshmem_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("IVSHMEM Kernel Module for Reading and Writing to Shared Memory");

