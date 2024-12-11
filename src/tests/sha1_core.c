#include "sha1_core.h"

#define ID "SHA1Core"

static const size_t MD_LEN = SHA1_MD_LEN;
static const size_t MSG_LEN = 0x10000;

static const size_t MD_OFF = 0;
static const size_t MSG_OFF = MD_OFF + SHA1_MD_LEN;
static const size_t BLOCK_LEN = MSG_OFF + MSG_LEN;

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

static bool sha1_core_tag(RSPCore *ctx, Bytes tag)
{
    return true;
}

static bool sha1_core_key_val_set(SHA1Core *ctx, Bytes key, Bytes val)
{
    ctx->is_set = true;
    if (bytes_equal_string(key, "Len"))
    {
        return dec_val(val, &ctx->len);
    }
    if (bytes_equal_string(key, "Msg"))
    {
        return hex_val(val, &ctx->msg, MSG_LEN);
    }
    if (bytes_equal_string(key, "MD"))
    {
        return hex_val(val, &ctx->md, MD_LEN);
    }
    fprintf(stderr, ID ": unknown key: ");
    bytes_fprintln_chr(key, stderr);
    return false;
}

static bool sha1_core_key_val(RSPCore *ctx, Bytes key, Bytes val)
{
    return sha1_core_key_val_set((SHA1Core *)ctx, key, val);
}

static bool sha1_core_check(SHA1Core *ctx)
{
    if (!ctx->is_set)
    {
        return true;
    }
    ctx->is_set = false;
    if (ctx->len > MSG_LEN)
    {
        fprintf(stderr, ID ": Len overflow: %lu\n", ctx->len);
        return false;
    }
    uint8_t store[20] = {};
    Bytes md = bytes_with(store, 20);
    SHA1_CTX sha1_ctx;
    sha1_init(&sha1_ctx);
    if (sha1_update(&sha1_ctx, ctx->msg.ptr, ctx->len / 8))
    {
        sha1_final(&sha1_ctx, md.ptr);
    }
    if (bytes_equal(ctx->md, md))
    {
        return true;
    }
    fprintf(stderr, ID ": FAIL:\n");
    fprintf(stderr, "Len: %lu\n", ctx->len);
    fprintf(stderr, "Msg: ");
    bytes_fprintln_hex(ctx->msg, stderr);
    fprintf(stderr, "MD< ");
    bytes_fprintln_hex(ctx->md, stderr);
    fprintf(stderr, "MD> ");
    bytes_fprintln_hex(md, stderr);
    return false;
}

static bool sha1_core_go(RSPCore *ctx)
{
    return sha1_core_check((SHA1Core *)ctx);
}

SHA1Core sha1_core_create()
{
    uint8_t *byte_store = (uint8_t *)malloc(BLOCK_LEN);
    if (byte_store == NULL)
    {
        fprintf(stderr, ID ": create: malloc NULL\n");
        exit(1);
    }
    return (SHA1Core){
        .core = (RSPCore){
            .tag = sha1_core_tag,
            .key_val = sha1_core_key_val,
            .go = sha1_core_go,
        },
        .is_set = false,
        .byte_store = byte_store,
        .len = 0,
        .md = bytes_with(byte_store + MD_OFF, 0),
        .msg = bytes_with(byte_store + MSG_OFF, 0),
    };
}

void sha1_core_destroy(SHA1Core *ctx)
{
    free(ctx->byte_store);
    ctx->is_set = false;
    ctx->len = 0;
    ctx->md = bytes_null();
    ctx->msg = bytes_null();
}
