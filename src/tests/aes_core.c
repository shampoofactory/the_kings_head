#include "aes_core.h"

#include <stdlib.h>

#include "aes.h"

#define ID "AESCore"

static const size_t KEY_LEN = 0x20;
static const size_t IV_LEN = 0x10;
static const size_t MSG_LEN = 0x1000;

static const size_t KEY_OFF = 0;
static const size_t IV_OFF = KEY_LEN;
static const size_t PLAINTEXT_OFF = IV_OFF + IV_LEN;
static const size_t CIPHERTEXT_OFF = PLAINTEXT_OFF + MSG_LEN;
static const size_t OUTTEXT_OFF = CIPHERTEXT_OFF + MSG_LEN;
static const size_t BLOCK_LEN = OUTTEXT_OFF + MSG_LEN;

static bool dec_val(Bytes src, uint64_t *dst)
{
    if (bytes_parse_uint64(src, dst))
    {
        return true;
    }
    fprintf(stderr, ID ": bad decimal value: ");
    bytes_fprintln_chr(src, stderr);
    return false;
}

static bool hex_val(Bytes src, Bytes *dst, size_t dst_len)
{
    dst->len = dst_len;
    if (bytes_parse_hex(src, dst))
    {
        return true;
    }
    fprintf(stderr, ID ": bad hex value: ");
    bytes_fprintln_chr(src, stderr);
    return false;
}

static bool aes_core_tag_set(AESCore *ctx, Bytes tag)
{
    if (bytes_equal_string(tag, "[ENCRYPT]"))
    {
        ctx->is_encrypt = true;
        return true;
    }
    if (bytes_equal_string(tag, "[DECRYPT]"))
    {
        ctx->is_encrypt = false;
        return true;
    }
    fprintf(stderr, ID ": unknown tag: ");
    bytes_fprintln_chr(tag, stderr);
    return false;
}

static bool aes_core_tag(RSPCore *ctx, Bytes tag)
{
    return aes_core_tag_set((AESCore *)ctx, tag);
}

static bool aes_core_key_val_set(AESCore *ctx, Bytes key, Bytes val)
{
    ctx->is_set = true;
    if (bytes_equal_string(key, "COUNT"))
    {
        return dec_val(val, &ctx->count);
    }
    if (bytes_equal_string(key, "KEY"))
    {
        return hex_val(val, &ctx->key, KEY_LEN);
    }
    if (bytes_equal_string(key, "IV"))
    {
        return hex_val(val, &ctx->iv, IV_LEN);
    }
    if (bytes_equal_string(key, "PLAINTEXT"))
    {
        return hex_val(val, &ctx->plaintext, MSG_LEN);
    }
    if (bytes_equal_string(key, "CIPHERTEXT"))
    {
        return hex_val(val, &ctx->ciphertext, MSG_LEN);
    }
    fprintf(stderr, ID ": unknown key: ");
    bytes_fprintln_chr(key, stderr);
    return false;
}

static bool aes_core_key_val(RSPCore *ctx, Bytes key, Bytes val)
{
    return aes_core_key_val_set((AESCore *)ctx, key, val);
}

static bool aes_core_check_fail(AESCore *ctx)
{
    fprintf(stderr, ID ": FAIL:\n");
    fprintf(stderr, "COUNT: %lu\n", ctx->count);
    fprintf(stderr, "MODE: %s\n", ctx->is_encrypt ? "ENCRYPT" : "DECRYPT");
    fprintf(stderr, "KEY: ");
    bytes_fprintln_hex(ctx->key, stderr);
    fprintf(stderr, "IV: ");
    bytes_fprintln_hex(ctx->iv, stderr);
    fprintf(stderr, "PLAINTEXT: ");
    bytes_fprintln_hex(ctx->plaintext, stderr);
    fprintf(stderr, "CIPHERTEXT: ");
    bytes_fprintln_hex(ctx->ciphertext, stderr);
    fprintf(stderr, "OUTTEXT: ");
    bytes_fprintln_hex(ctx->outtext, stderr);
    return false;
}

static bool aes_core_256_ofb_decrypt(AESCore *ctx)
{
    ctx->outtext.len = ctx->ciphertext.len;
    AES256_KS_ENC ks;
    aes256_ks_enc_gen(&ks, ctx->key.ptr);
    aes256_ofb_decrypt(ctx->outtext.ptr,
                       ctx->ciphertext.ptr,
                       &ks,
                       _mm_load_si128((__m128i *)ctx->iv.ptr),
                       ctx->ciphertext.len);
    return bytes_equal(ctx->outtext, ctx->plaintext)
               ? true
               : aes_core_check_fail(ctx);
}

static bool aes_core_256_ofb_encrypt(AESCore *ctx)
{
    ctx->outtext.len = ctx->ciphertext.len;
    AES256_KS_ENC ks;
    aes256_ks_enc_gen(&ks, ctx->key.ptr);
    aes256_ofb_encrypt(ctx->outtext.ptr,
                       ctx->plaintext.ptr,
                       &ks,
                       _mm_load_si128((__m128i *)ctx->iv.ptr),
                       ctx->plaintext.len);
    return bytes_equal(ctx->outtext, ctx->ciphertext)
               ? true
               : aes_core_check_fail(ctx);
}

static bool aes_core_check(AESCore *ctx)
{
    if (!ctx->is_set)
    {
        return true;
    }
    ctx->is_set = false;
    return ctx->is_encrypt ? aes_core_256_ofb_encrypt(ctx)
                           : aes_core_256_ofb_decrypt(ctx);
}

static bool aes_core_go(RSPCore *ctx)
{
    return aes_core_check((AESCore *)ctx);
}
#include <immintrin.h>

AESCore aes_core_256_ofb_create()
{
    uint8_t *byte_store = (uint8_t *)malloc(BLOCK_LEN);
    if (byte_store == NULL)
    {
        fprintf(stderr, ID ": create: malloc NULL\n");
        exit(1);
    }
    return (AESCore){
        .core = (RSPCore){
            .tag = aes_core_tag,
            .key_val = aes_core_key_val,
            .go = aes_core_go,
        },
        .is_set = false,
        .is_encrypt = false,
        .byte_store = byte_store,
        .count = 0,
        .key = bytes_with(byte_store + KEY_OFF, 0),
        .iv = bytes_with(byte_store + IV_OFF, 0),
        .plaintext = bytes_with(byte_store + PLAINTEXT_OFF, 0),
        .ciphertext = bytes_with(byte_store + CIPHERTEXT_OFF, 0),
        .outtext = bytes_with(byte_store + OUTTEXT_OFF, 0),
    };
}

void aes_core_destroy(AESCore *ctx)
{
    free(ctx->byte_store);
    ctx->is_set = false;
    ctx->is_encrypt = false;
    ctx->count = 0;
    ctx->key = bytes_null();
    ctx->iv = bytes_null();
    ctx->plaintext = bytes_null();
    ctx->ciphertext = bytes_null();
    ctx->outtext = bytes_null();
}
