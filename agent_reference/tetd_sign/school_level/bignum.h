#ifndef __BIGNUM_H__
#define __BIGNUM_H__

/* This macro defines the word size in bytes of the array that constitues the big-number data structure. */
#ifndef WORD_SIZE
  #define WORD_SIZE 4
#endif

#define BN_ARRAY_SIZE    ((384 / WORD_SIZE) + 1)

/* Here comes the compile-time specialization for how large the underlying array size should be. */
/* The choices are 1, 2 and 4 bytes in size with uint32, uint64 for WORD_SIZE==4, as temporary. */
#ifndef WORD_SIZE
  #error Must define WORD_SIZE to be 1, 2, 4
#elif (WORD_SIZE == 1)
  /* Data type of array in structure */
  #define DTYPE                    uint8_t
  /* bitmask for getting MSB */
  #define DTYPE_MSB                ((DTYPE_TMP)(0x80))
  /* Data-type larger than DTYPE, for holding intermediate results of calculations */
  #define DTYPE_TMP                uint32_t
  /* sprintf format string */
  #define SPRINTF_FORMAT_STR       "%.02x"
  #define SSCANF_FORMAT_STR        "%2hhx"
  /* Max value of integer type */
  #define MAX_VAL                  ((DTYPE_TMP)0xFF)
#elif (WORD_SIZE == 2)
  #define DTYPE                    uint16_t
  #define DTYPE_TMP                uint32_t
  #define DTYPE_MSB                ((DTYPE_TMP)(0x8000))
  #define SPRINTF_FORMAT_STR       "%.04x"
  #define SSCANF_FORMAT_STR        "%4hx"
  #define MAX_VAL                  ((DTYPE_TMP)0xFFFF)
#elif (WORD_SIZE == 4)
  #define DTYPE                    unsigned int
  #define DTYPE_TMP                unsigned long long
  #define DTYPE_MSB                ((DTYPE_TMP)(0x80000000))
  #define SPRINTF_FORMAT_STR       "%.08x"
  #define SSCANF_FORMAT_STR        "%8x"
  #define MAX_VAL                  ((DTYPE_TMP)0xFFFFFFFF)
#endif
#ifndef DTYPE
  #error DTYPE must be defined to uint8_t, uint16_t uint32_t or whatever
#endif

/* Custom assert macro - easy to disable */
#define require(p, msg) assert(p && #msg)

/* Data-holding structure: array of DTYPEs */
struct bn
{
  DTYPE array[BN_ARRAY_SIZE];
};

/* Tokens returned by bignum_cmp() for value comparison */
enum { SMALLER = -1, EQUAL = 0, LARGER = 1 };

/* Initialization functions: */
void bignum_init(struct bn* n);
void bignum_from_int(struct bn* n, DTYPE_TMP i);
int  bignum_to_int(struct bn* n);
void bignum_from_string(struct bn* n, char* str, int nbytes);
void bignum_to_string(struct bn* n, char* str, int maxsize);

/* Basic arithmetic operations: */
void bignum_add(struct bn* a, struct bn* b, struct bn* c); /* c = a + b */
void bignum_sub(struct bn* a, struct bn* b, struct bn* c); /* c = a - b */
void bignum_mul(struct bn* a, struct bn* b, struct bn* c); /* c = a * b */
void bignum_div(struct bn* a, struct bn* b, struct bn* c); /* c = a / b */
void bignum_mod(struct bn* a, struct bn* b, struct bn* c); /* c = a % b */
void bignum_divmod(struct bn* a, struct bn* b, struct bn* c, struct bn* d); /* c = a/b, d = a%b */

/* Bitwise operations: */
void bignum_and(struct bn* a, struct bn* b, struct bn* c); /* c = a & b */
void bignum_or(struct bn* a, struct bn* b, struct bn* c);  /* c = a | b */
void bignum_xor(struct bn* a, struct bn* b, struct bn* c); /* c = a ^ b */
void bignum_lshift(struct bn* a, struct bn* b, int nbits); /* b = a << nbits */
void bignum_rshift(struct bn* a, struct bn* b, int nbits); /* b = a >> nbits */

/* Special operators and comparison */
int  bignum_cmp(struct bn* a, struct bn* b);               /* Compare: returns LARGER, EQUAL or SMALLER */
int  bignum_is_zero(struct bn* n);                         /* For comparison with zero */
void bignum_inc(struct bn* n);                             /* Increment: add one to n */
void bignum_dec(struct bn* n);                             /* Decrement: subtract one from n */
void bignum_pow(struct bn* a, struct bn* b, struct bn* c); /* Calculate a^b -- e.g. 2^10 => 1024 */
void bignum_isqrt(struct bn* a, struct bn* b);             /* Integer square root -- e.g. isqrt(5) => 2*/
void bignum_assign(struct bn* dst, struct bn* src);        /* Copy src into dst -- dst := src */      /* Copy src into dst -- dst := src */

/* Utility Functions */
int bignum_getbit(struct bn* a, int n);
int bignum_numbits(struct bn* bn);
void bignum_print(struct bn* num);

#endif /* #ifndef __BIGNUM_H__ */
