#ifndef SHA1_H_982988038BDE4D84
#define SHA1_H_982988038BDE4D84

#include <stdbool.h>
#include <stdint.h>

#define SHA1_BLK_LEN 0x40

#define SHA1_MD_LEN 0x14

typedef struct __attribute__((aligned(16)))
{
    uint8_t hash[SHA1_MD_LEN];
    uint64_t len;
    uint8_t blk[SHA1_BLK_LEN];
} SHA1_CTX;

void sha1_final(SHA1_CTX *ctx, uint8_t md[static SHA1_MD_LEN]);

void sha1_init(SHA1_CTX *ctx);

bool sha1_update(SHA1_CTX *ctx, const uint8_t *msg, uint64_t msg_len);

void sha1_wipe(SHA1_CTX *ctx);

#endif
