#ifndef HMAC_SHA1_H_25DFBB1EB662B3BB
#define HMAC_SHA1_H_25DFBB1EB662B3BB

#include <immintrin.h>
#include <stdint.h>

#define AES256_BLK_LEN 0X10
#define AES256_KEY_LEN 0x20
#define AES256_KEY_SCHEDULE_LEN 0xF0

// AES256 encrypt key schedule
typedef struct __attribute__((aligned(16)))
{
    uint8_t hash[AES256_KEY_SCHEDULE_LEN];
} AES256_KS_ENC;

// AES256 decrypt key schedule
typedef struct __attribute__((aligned(16)))
{
    uint8_t hash[AES256_KEY_SCHEDULE_LEN];
} AES256_KS_DEC;

// AES256 OFB encrypt
// Return feedback for next block/ iv
__m128i aes256_ofb_encrypt(uint8_t *dst, const uint8_t *src, AES256_KS_ENC *ks, __m128i iv, uint64_t n_bytes);

// AES256 OFB decrypt
// Return feedback for next block/ iv
__m128i aes256_ofb_decrypt(uint8_t *dst, const uint8_t *src, AES256_KS_ENC *ks, __m128i iv, uint64_t n_bytes);

// AES256 encrypt key schedule generation
void aes256_ks_enc_gen(AES256_KS_ENC *ctx, uint8_t key[static AES256_KEY_LEN]);

// AES256 decrypt key schedule generation
void aes256_ks_dec_gen(AES256_KS_DEC *ctx, AES256_KS_ENC *src);

// AES256 wipe encrypt key schedule
void aes256_ks_enc_wipe(AES256_KS_ENC *ctx);

// AES256 wipe decrypt key schedule
void aes256_ks_dec_wipe(AES256_KS_ENC *ctx);

#endif
