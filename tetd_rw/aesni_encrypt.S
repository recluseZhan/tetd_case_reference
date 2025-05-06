#include <linux/linkage.h>
#include <asm/ibt.h>  // for RET macro

.text
SYM_FUNC_START(aes_encrypt_128)

    movdqu (%rdi), %xmm0      // load input
    movdqu (%rdx), %xmm1      // load key

    pxor %xmm1, %xmm0
    aesenc %xmm1, %xmm0
    aesenc %xmm1, %xmm0
    aesenc %xmm1, %xmm0
    aesenc %xmm1, %xmm0
    aesenc %xmm1, %xmm0
    aesenc %xmm1, %xmm0
    aesenc %xmm1, %xmm0
    aesenc %xmm1, %xmm0
    aesenc %xmm1, %xmm0
    aesenclast %xmm1, %xmm0

    movdqu %xmm0, (%rsi)      // store result

    RET

SYM_FUNC_END(aes_encrypt_128)

