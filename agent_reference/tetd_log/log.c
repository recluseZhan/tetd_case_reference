#include <linux/module.h>
#include <linux/tty.h>
//#include <linux/io.h>
MODULE_LICENSE("GPL");

#define PAGE_SIZE 4096
#define GPA 0x17485b000
//#define GPA2 0x1000
#define SIZE 128
#define AES_BLOCK_SIZE 16
static char* page_memory = NULL;
//static char __iomem *vaddr;

extern void aes_gcm_encrypt(u8 *dst, const u8 *src);
int log_copy(void){
    if(page_memory == NULL){
        page_memory = (char *)__get_free_pages(GFP_KERNEL, 0);
    }
    char* va = (char *)phys_to_virt((phys_addr_t)GPA);
 
    memcpy(page_memory,va,SIZE);
    pr_info("Data at mapped address: %s\n", va);

    return 0;
}
int log_copy2(void){
    if(page_memory == NULL){
        page_memory = (char *)__get_free_pages(GFP_KERNEL, 0);
    }
    //char* va = (char *)phys_to_virt((phys_addr_t)GPA2);
    //memcpy(page_memory,va,SIZE);
    //pr_info("Data at mapped address: %s\n", va);

    return 0;
}
/*
int log_copy(void){
    struct task_struct *task = current;  
    struct tty_struct *tty = task->signal->tty;
    struct timespec64 ts;

    char info_str_login[128];
    char *page_memory;  
    size_t info_len; 
    
    page_memory = (char *)__get_free_pages(GFP_KERNEL, 0);

    if (!page_memory) {
        pr_err("Failed to allocate memory page.\n");
        return -ENOMEM;
    }

    ktime_get_real_ts64(&ts);
    snprintf(info_str_login, sizeof(info_str_login),
        "PID: %d, UID: %d, TTY: %s, Session ID: %d, Current time: %lld.%09lld",
        task->pid,
        task->cred->uid.val,
        tty ? tty->name : "No TTY",
        task->sessionid,
        ts.tv_sec, ts.tv_nsec);
    //pr_info("Process Info: %s\n", info_str_login);    
    info_len = strlen(info_str_login);

    //if (info_len + 4 > PAGE_SIZE) {
    //    pr_warn("String is too long to fit in a single page!\n");
    //    return -ENOMEM;
    //}

    memcpy(page_memory,info_str_login,info_len);
    //snprintf(page_memory, info_len + 4, "%sEND", info_str_login);

    pr_info("info size:%d", info_len);
    //pr_info("Page memory address: %p\n", page_memory);
    //pr_info("Page content: %s\n", page_memory);

    return 0;
}
int log_copy2(void){
    struct task_struct *task = current;
    struct tty_struct *tty = task->signal->tty;
    struct timespec64 ts;

    char info_str_module[128];
    char *page_memory2; 
    size_t info_len;

    page_memory2 = (char *)__get_free_pages(GFP_KERNEL, 0);

    if (!page_memory2) {
        pr_err("Failed to allocate memory page.\n");
        return -ENOMEM;
    }

    ktime_get_real_ts64(&ts);
    snprintf(info_str_module, sizeof(info_str_module),
       "NAME: module, UID: %d, PPID: %d, Parent Process Name: %s, Current time: %lld.%09lld",
       task->cred->uid.val,
       task->real_parent->pid,
       task->real_parent->comm,
       ts.tv_sec, ts.tv_nsec);
    info_len = strlen(info_str_module);

    //if (info_len + 4 > PAGE_SIZE) {
    //    pr_warn("String is too long to fit in a single page!\n");
    //    return -ENOMEM;
    //}

    memcpy(page_memory2,info_str_module,info_len);
    //snprintf(page_memory2, info_len + 4, "%sEND", info_str_module);

    pr_info("info size:%d", info_len);
    //pr_info("Page memory address: %p\n", page_memory2);
    //pr_info("Page content: %s\n", page_memory2);
    
    return 0;
}*/
/*
*/

unsigned long work_encrypt(const u8 *input, u8 *output, size_t len){
    for (int i = 0; i < PAGE_SIZE / AES_BLOCK_SIZE; i++) {
        aes_gcm_encrypt(output + i * AES_BLOCK_SIZE, input + i * AES_BLOCK_SIZE);
    }
    return 0;
}

static int __init log_init(void)
{
    printk(KERN_INFO "Entering log module\n");
    //vaddr = ioremap(GPA, SIZE);
    //if (!vaddr) {
    //    pr_err("Failed to map physical address 0x%lx\n", (unsigned long)GPA);
    //    return -ENOMEM;
    //}
    return 0;
}

static void __exit log_exit(void)
{
    printk(KERN_INFO "Exiting log module\n");
     //if (vaddr) {
    //    iounmap(vaddr);  
    //    pr_info("Unmapped virtual address: %p\n", vaddr);
    //}
}
EXPORT_SYMBOL(log_copy);
EXPORT_SYMBOL(log_copy2);
module_init(log_init);
module_exit(log_exit);

