#ifndef AESNI_ENCRYPT_H
#define AESNI_ENCRYPT_H

#include <linux/types.h>

int aes_encrypt_128(const u8 *in, u8 *out, const u8 *key);

#endif

