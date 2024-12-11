#ifndef TOTP_CORE_H_AC472FE78492DA1F
#define TOTP_CORE_H_AC472FE78492DA1F

#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>

#include "aes.h"
#include "hmac_sha1.h"

typedef struct __attribute__((packed))
{
    uint8_t data_key[AES256_KEY_LEN];
    uint8_t hmac_key[SHA1_MD_LEN];
    uint8_t salt[AES256_KEY_LEN];
    uint64_t iter;
} TotpKeys;

TotpKeys totp_keys_gen(const uint8_t *pass, uint32_t pass_len, uint64_t iter, const uint8_t salt[AES256_KEY_LEN]);

void totp_keys_wipe(TotpKeys *keys);

typedef struct __attribute__((packed))
{
    uint8_t key[SHA1_MD_LEN];
    uint32_t n_digits;
    uint32_t period;
} TotpParam;

TotpParam totp_param_with(const uint8_t *key, size_t key_len, uint32_t n_digits, uint32_t period);

void totp_param_wipe(TotpParam *param);

typedef struct __attribute__((packed))
{
    uint8_t salt[AES256_KEY_LEN];
    uint8_t hmac[SHA1_MD_LEN];
    uint32_t iter;
    uint8_t param_enc[sizeof(TotpParam)];
} TotpBlk;

void totp_blk_wipe(TotpBlk *blk);

TotpBlk totp_blk_encrypt(const TotpParam *param, TotpKeys *keys);

bool totp_blk_decrypt(const TotpBlk *blk, TotpParam *param, const uint8_t *pass, uint32_t pass_len);

#endif
