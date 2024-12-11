#ifndef HMAC_SHA1_H_5FBA3AB6B63033E4
#define HMAC_SHA1_H_5FBA3AB6B63033E4

#include <stdint.h>

#include "sha1.h"

typedef struct __attribute__((aligned(16)))
{
    SHA1_CTX sha1_ctx;
    uint8_t opad_key[SHA1_MD_LEN];
    uint8_t ipad_key[SHA1_MD_LEN];
} HMAC_SHA1_CTX;

void hmac_sha1_init(HMAC_SHA1_CTX *ctx, const uint8_t *key, uint32_t key_len);

bool hmac_sha1_update(HMAC_SHA1_CTX *ctx, const uint8_t *msg, uint64_t msg_len);

void hmac_sha1_final(HMAC_SHA1_CTX *ctx, uint8_t md[static SHA1_MD_LEN]);

void hmac_sha1_wipe(HMAC_SHA1_CTX *ctx);

#endif
