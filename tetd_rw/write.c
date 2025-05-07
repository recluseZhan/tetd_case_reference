#include <linux/module.h>
#include <linux/scatterlist.h>
#include "aesni_encrypt.h"

#define AES_KEY_SIZE 16
#define AES_BLOCK_SIZE 16
#define GHASH_POLY 0xe1u

extern int aes_encrypt_128(const u8 *input, u8 *output, const u8 *key);

// NIST standard "carry-less multiplication + reduction" on GF(2^128).
// Xi[16], H[16] -> Z[16]
static void ghash_mul_block(const u8 Xi[16], const u8 H[16], u8 Z[16])
{
    u8 V[16], Zt[16] = {0};
    int i, bit;

    // V = H
    memcpy(V, H, 16);

    // Manipulate X bitwise.
    for (i = 0; i < 16; i++) {
        for (bit = 7; bit >= 0; bit--) {
            if ((Xi[i] >> bit) & 1) {
                // Zt ^= V
                int j;
                for (j = 0; j < 16; j++)
                    Zt[j] ^= V[j];
            }
            // Calculate V = V >> 1; if the lowest bit is 1, then V ^= R.
            {
                int lsb = V[15] & 1;
                // Shift right 1 bit overall.
                for (int k = 15; k > 0; k--)
                    V[k] = (V[k] >> 1) | ((V[k-1] & 1) << 7);
                V[0] >>= 1;
                if (lsb) {
                    // R = 0xe1 0000...00
                    V[0] ^= GHASH_POLY;
                }
            }
        }
    }
    memcpy(Z, Zt, 16);
}

// aes-gcm
// key: 16 bytes, iv: 12 bytes, pt: plaintext, len: plaintext length.
// ct: ciphertext buffer (at least len bytes), tag: 16-byte buffer.
static void gcm_encrypt(const u8 *key, const u8 *iv, const u8 *pt, size_t len, u8 *ct, u8 *tag)
{
    u8 H[16], J0[16], E0[16], Yi[16], buf[16];
    size_t i, full_blocks = len / 16;
    size_t rem = len % 16;

    // H = AES_K(0^128)
    memset(buf, 0, 16);
    aes_encrypt_128(buf, H, key);

    // J0 = IV || 0x00000001
    memcpy(J0, iv, 12);
    J0[12] = J0[13] = J0[14] = 0;
    J0[15] = 1;

    // E0 = AES_K(J0)
    aes_encrypt_128(J0, E0, key);

    // GHASH Y0 = 0
    memset(Yi, 0, 16);

    // CTR block cipher + GHASH updates.
    for (i = 0; i < full_blocks; i++) {
        u8 ctr_blk[16];
        memcpy(ctr_blk, J0, 16);
        {
            u32 ctr = cpu_to_be32((u32)(i + 1));
            memcpy(&ctr_blk[12], &ctr, 4);
        }
        // keystream = AES_K(ctr_blk)
        aes_encrypt_128(ctr_blk, buf, key);

        // XOR plaintext -> ciphertext, and GHASH update.
        for (int j = 0; j < 16; j++) {
            ct[i*16 + j] = pt[i*16 + j] ^ buf[j];
            buf[j] = ct[i*16 + j];
        }
        ghash_mul_block(buf, H, Yi);
    }

    if (rem) {
        u8 ctr_blk[16];
        memcpy(ctr_blk, J0, 16);
        {
            u32 ctr = cpu_to_be32((u32)(full_blocks + 1));
            memcpy(&ctr_blk[12], &ctr, 4);
        }
        aes_encrypt_128(ctr_blk, buf, key);
        for (int j = 0; j < rem; j++) {
            ct[full_blocks*16 + j] = pt[full_blocks*16 + j] ^ buf[j];
            buf[j] = ct[full_blocks*16 + j];
        }
        for (int j = rem; j < 16; j++)
            buf[j] = 0;
        ghash_mul_block(buf, H, Yi);
    }

    // L = [0^64 || bit_len(plaintext)^64]
    {
        u8 len_blk[16] = {0};
        u64 bits = (u64)len * 8;
        u64 be_bits = cpu_to_be64(bits);
        memcpy(&len_blk[8], &be_bits, 8);
        for (int j = 0; j < 16; j++)
            buf[j] = Yi[j] ^ len_blk[j];
        ghash_mul_block(buf, H, Yi);
    }

    // Tag
    for (int j = 0; j < 16; j++)
        tag[j] = E0[j] ^ Yi[j];
}

static const u8 test_key[16] = {
    0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
    0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff
};
static const u8 test_iv[12] = {
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    0x18,0x19,0x1a,0x1b
};
u8 tag[16];

unsigned long work_encrypt(const u8 *input, u8 *output, size_t len){
    gcm_encrypt(test_key, test_iv, input, len, output, tag);
    printk("tag=%*phN\n", 16, tag); 
    //for (int i = 0; i < PAGE_SIZE / AES_BLOCK_SIZE; i++) {
    //    aes_encrypt_128(input + i * AES_BLOCK_SIZE, output + i * AES_BLOCK_SIZE, aes_key);
    //}
    return 0;
}

#define IVSHMEM_BAR0_ADDRESS 0x383800000000  // BAR 2 addr
#define IVSHMEM_BAR0_SIZE (1 * 1024 * 1024)  // BAR 2 size
void __iomem *ivshmem_base;

#define ORDER 6
#define RING_BUFFER_SIZE (256 * 1024)  // 256KB
#define PAGE_SIZE 4096

char* shared_mem;
unsigned long head = 0;
unsigned long tail = 0;

void write_to_buffer(unsigned long phys_addr, unsigned long len) {
    unsigned long bytes_written = 0;
    //unsigned long phys_addr = 0x00900000;
    void *data = phys_to_virt(phys_addr);
    //data = memremap(phys_addr, PAGE_SIZE, MEMREMAP_WB);
    while (bytes_written < len) {
        while (((head + 1) % RING_BUFFER_SIZE) == tail) {
            cpu_relax();  
        }	
	//memset(ivshmem_base,1,RING_BUFFER_SIZE);
	work_encrypt(data+bytes_written,ivshmem_base+head,PAGE_SIZE);
        //memcpy(ivshmem_base+head,data+bytes_written,PAGE_SIZE);
	head = (head+PAGE_SIZE) % RING_BUFFER_SIZE;
	bytes_written += PAGE_SIZE;
    }
}

void write_kernel_to_buffer(unsigned long phys_addr, unsigned long len){
    write_to_buffer(phys_addr, len);
}
static int __init write_module_init(void)
{
    
    shared_mem = __get_free_pages(GFP_KERNEL,ORDER);
    if (!shared_mem) {
        pr_err("Failed to allocate shared memory\n");
        return -ENOMEM;
    }
    ivshmem_base = ioremap(IVSHMEM_BAR0_ADDRESS, IVSHMEM_BAR0_SIZE);
    if (!ivshmem_base) {
        pr_err("Could not map ivshmem memory\n");
        return -EIO;
    }
    pr_info("Writer module loaded\n");
    return 0;
}

static void __exit write_module_exit(void)
{
    free_pages(shared_mem,ORDER);
    if (ivshmem_base) {
        iounmap(ivshmem_base);
        pr_info("ivshmem memory unmapped\n");
    }
    pr_info("Writer module unloaded\n");
}
EXPORT_SYMBOL(shared_mem);
EXPORT_SYMBOL(head);
EXPORT_SYMBOL(tail);
EXPORT_SYMBOL(write_to_buffer);
EXPORT_SYMBOL(write_kernel_to_buffer);

module_init(write_module_init);
module_exit(write_module_exit);
MODULE_LICENSE("GPL");
