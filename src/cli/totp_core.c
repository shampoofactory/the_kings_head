#include "totp_core.h"

#include <immintrin.h>
#include <string.h>

#include "pbkdf2_hmac_sha1.h"
#include "totp.h"

TotpKeys totp_keys_gen(const uint8_t *pass, uint32_t pass_len, uint64_t iter, const uint8_t salt[AES256_KEY_LEN])
{
    TotpKeys keys;
    keys.iter = iter;
    if (salt == NULL)
    {
        arc4random_buf(keys.salt, sizeof(keys.salt));
    }
    else
    {
        memcpy(keys.salt, salt, sizeof(keys.salt));
    }
    pbkdf2_hmac_sha1(pass, pass_len,
                     keys.salt, sizeof(keys.salt),
                     iter,
                     sizeof(keys.data_key) + sizeof(keys.hmac_key), (uint8_t *)&keys);
    return keys;
}

void totp_keys_wipe(TotpKeys *keys)
{
    memset(keys, 0, sizeof(*keys));
}

TotpParam totp_param_with(const uint8_t *key, size_t key_len, uint32_t n_digits, uint32_t period)
{
    TotpParam param = {};
    param.n_digits = n_digits;
    param.period = period;
    if (key_len <= sizeof(param.key))
    {
        // Copy key
        memcpy(param.key, key, key_len);
    }
    else
    {
        // Compress key
        SHA1_CTX ctx;
        sha1_init(&ctx);
        sha1_update(&ctx, param.key, key_len);
        sha1_final(&ctx, param.key);
    }
    return param;
}

void totp_param_wipe(TotpParam *param)
{
    memset(param, 0, sizeof(*param));
}

void totp_blk_wipe(TotpBlk *blk)
{
    memset(blk, 0, sizeof(*blk));
}

TotpBlk totp_blk_encrypt(const TotpParam *param, TotpKeys *keys)
{
    TotpBlk blk;
    memcpy(blk.salt, keys->salt, sizeof(keys->salt));
    blk.iter = keys->iter;
    AES256_KS_ENC ks;
    aes256_ks_enc_gen(&ks, keys->data_key);
    aes256_ofb_encrypt((uint8_t *)&blk.param_enc, (uint8_t *)param, &ks, _mm_setzero_si128(), sizeof(blk.param_enc));
    aes256_ks_enc_wipe(&ks);
    HMAC_SHA1_CTX ctx;
    hmac_sha1_init(&ctx, keys->hmac_key, sizeof(keys->hmac_key));
    hmac_sha1_update(&ctx, (uint8_t *)&blk.param_enc, sizeof(blk.param_enc));
    hmac_sha1_final(&ctx, blk.hmac);
    return blk;
}

bool totp_blk_decrypt(const TotpBlk *blk, TotpParam *param, const uint8_t *pass, uint32_t pass_len)
{

    TotpKeys keys = totp_keys_gen(pass, pass_len, blk->iter, blk->salt);
    uint8_t hmac[SHA1_MD_LEN];
    HMAC_SHA1_CTX ctx;
    hmac_sha1_init(&ctx, keys.hmac_key, sizeof(keys.hmac_key));
    hmac_sha1_update(&ctx, (uint8_t *)&blk->param_enc, sizeof(blk->param_enc));
    hmac_sha1_final(&ctx, hmac);
    if (memcmp(hmac, blk->hmac, sizeof(hmac)))
    {
        return false;
    }
    AES256_KS_ENC ks;
    aes256_ks_enc_gen(&ks, keys.data_key);
    aes256_ofb_decrypt((uint8_t *)param, (uint8_t *)&blk->param_enc, &ks, _mm_setzero_si128(), sizeof(blk->param_enc));
    aes256_ks_enc_wipe(&ks);
    return true;
}
