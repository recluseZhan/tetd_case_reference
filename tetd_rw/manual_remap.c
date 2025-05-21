#include <linux/module.h>
#include <asm/io.h>

#define PAGE_SHIFT    12UL
#define PAGE_SIZE     (1UL << PAGE_SHIFT)
#define PAGE_MASK     (~(PAGE_SIZE - 1))
#define PTRS_PER_LVL  512UL

#define PTE_SHIFT     12UL
#define PMD_SHIFT     21UL
#define PUD_SHIFT     30UL
#define P4D_SHIFT     39UL
#define PGD_SHIFT     48UL

//#define PHYS_START    0x00900000UL
//#define PHYS_END      0x00900fffUL
#define PTE_FLAGS   (_PAGE_PRESENT | _PAGE_RW | _PAGE_PWT | _PAGE_PCD)  // 0x1A3
#define VSTART_ADDR 0xffa0000000000000UL

extern unsigned long __get_free_pages(unsigned int gfp_mask, unsigned int order);

static inline unsigned long read_cr3(void)
{
    unsigned long val;
    asm volatile("mov %%cr3, %0" : "=r"(val));
    return val;
}

static inline void *phys_to_virt_k(unsigned long phys)
{
    return __va(phys);
}

static inline void manual_invlpg(unsigned long vaddr) {
    asm volatile("invlpg (%0)" ::"r" (vaddr) : "memory");
}

void manual_flush_tlb_kernel_range(unsigned long start, unsigned long end) {
    start = start & PAGE_MASK;
    end = ALIGN(end, PAGE_SIZE);
    for (; start < end; start += PAGE_SIZE) {
        manual_invlpg(start);
    }
}

static int manual_remap_range(unsigned long phys_start, unsigned long phys_end, unsigned long virt_start)
{
    unsigned long phys = phys_start & PAGE_MASK;
    unsigned long virt = virt_start & PAGE_MASK;
    unsigned long cr3 = read_cr3() & PAGE_MASK;
    unsigned long *pgd = phys_to_virt_k(cr3);
    unsigned long *p4d, *pud, *pmd, *pte;
    unsigned long ent;
    int i0,i1,i2,i3,i4;
    phys_end = phys_end & PAGE_MASK;

    for (; phys <= phys_end; phys += PAGE_SIZE, virt += PAGE_SIZE) {
        i0 = (virt >> PGD_SHIFT) & (PTRS_PER_LVL - 1);
        i1 = (virt >> P4D_SHIFT) & (PTRS_PER_LVL - 1);
        i2 = (virt >> PUD_SHIFT) & (PTRS_PER_LVL - 1);
        i3 = (virt >> PMD_SHIFT) & (PTRS_PER_LVL - 1);
        i4 = (virt >> PTE_SHIFT) & (PTRS_PER_LVL - 1);

        /* PML5/PGD */
        if (!(pgd[i0] & 1UL)) {
            unsigned long np = __get_free_pages(GFP_KERNEL | __GFP_ZERO, 0);
            if (!np) return -ENOMEM;
            pgd[i0] = (((unsigned long)np - PAGE_OFFSET) & PAGE_MASK) | 0x3UL;
	    //np = virt_to_phys((void *)np);
	    //pgd[i0] = (np & PAGE_MASK) | 0x3UL;
        }
        p4d = phys_to_virt_k(pgd[i0] & PAGE_MASK);

        /* P4D */
        if (!(p4d[i1] & 1UL)) {
            unsigned long np = __get_free_pages(GFP_KERNEL | __GFP_ZERO, 0);
            if (!np) return -ENOMEM;
            p4d[i1] = (((unsigned long)np - PAGE_OFFSET) & PAGE_MASK) | 0x3UL;
	    //np = virt_to_phys((void *)np);
	    //p4d[i1] = (np & PAGE_MASK) | 0x3UL;
        }
        pud = phys_to_virt_k(p4d[i1] & PAGE_MASK);

        /* PUD */
        if (!(pud[i2] & 1UL)) {
            unsigned long np = __get_free_pages(GFP_KERNEL | __GFP_ZERO, 0);
            if (!np) return -ENOMEM;
            pud[i2] = (((unsigned long)np - PAGE_OFFSET) & PAGE_MASK) | 0x3UL;
	    //np = virt_to_phys((void *)np);
	    //pud[i2] = (np & PAGE_MASK) | 0x3UL;
	    printk("get free page\n");
        }
        pmd = phys_to_virt_k(pud[i2] & PAGE_MASK);

        /* PMD */
        if (!(pmd[i3] & 1UL)) {
            unsigned long np = __get_free_pages(GFP_KERNEL | __GFP_ZERO, 0);
            if (!np) return -ENOMEM;
	    pmd[i3] = (((unsigned long)np - PAGE_OFFSET) & PAGE_MASK) | 0x3UL;
            //np = virt_to_phys((void *)np);
	    //pmd[i3] = (np & PAGE_MASK) | 0x3UL;
	    printk("get free page\n");
        }
        pte = phys_to_virt_k(pmd[i3] & PAGE_MASK);

        /* PTE */
        pte[i4] = (phys & PAGE_MASK) | PTE_FLAGS;
    }
    manual_flush_tlb_kernel_range(VSTART_ADDR, VSTART_ADDR + (phys_end - phys_start));
    return 0;
}

unsigned long manual_remap_work(unsigned long phys_start, unsigned long phys_end){
    int ret = 0;
    for(int i = 0; i < (phys_end - phys_start + 1) / PAGE_SIZE; i++){
        ret = manual_remap_range(phys_start + i * PAGE_SIZE, phys_end + i * PAGE_SIZE, VSTART_ADDR + i * PAGE_SIZE);
        if (ret) {
            pr_err("manual_remap_fullpt: remap_range failed %d\n", ret);
            return ret;
        }
    }
    pr_info("manual_remap_fullpt: mapping done. VSTART_ADDR:0x%lx\n", (unsigned long)VSTART_ADDR);
    return (unsigned long)VSTART_ADDR;
}

static int __init manual_remap_init(void)
{
    pr_info("manual_remap: module loaded\n");
    return 0;
}

static void __exit manual_remap_exit(void)
{
    pr_info("manual_remap: module unloaded\n");
}
EXPORT_SYMBOL(manual_remap_work);

module_init(manual_remap_init);
module_exit(manual_remap_exit);
MODULE_LICENSE("GPL");

