#include <stdlib.h>

#include "rsp.h"

RSPCore rsp_core_null()
{
    return (RSPCore){
        .tag = NULL,
        .key_val = NULL,
        .go = NULL,
    };
}

RSPVar rsp_var_null()
{
    return (RSPVar){
        .tag = bytes_null(),
        .key = bytes_null(),
        .val = bytes_null(),
        .comment = bytes_null(),
    };
}

RSP rsp_create(size_t rdr_len)
{
    return (RSP){
        .rdr = rdr_create(rdr_len),
        .core = NULL,
        .var = rsp_var_null(),
    };
}

void rsp_destroy(RSP *ctx)
{
    rdr_destroy(&ctx->rdr);
    ctx->core = NULL;
    ctx->var = rsp_var_null();
}

static RSPToken rsp_load_line(RSP *ctx)
{
    Bytes line = rdr_next(&ctx->rdr);
    if (bytes_is_null(line))
    {
        return RSPToken_EOF;
    }
    if (line.len == 0)
    {
        return RSPToken_NULL;
    }
    if (bytes_starts_with(line, '[') && bytes_ends_with(line, ']'))
    {
        ctx->var.tag = line;
        bytes_trim(&ctx->var.tag);
        return RSPToken_TAG;
    }
    if (bytes_starts_with(line, '#'))
    {
        ctx->var.comment = line;
        bytes_trim(&ctx->var.comment);
        return RSPToken_COMMENT;
    }
    int eq = bytes_index_of(line, '=');
    if (eq != -1)
    {
        ctx->var.key = bytes_head(line, eq);
        ctx->var.val = bytes_tail(line, eq + 1);
        bytes_trim(&ctx->var.key);
        bytes_trim(&ctx->var.val);
        return RSPToken_KEY_VAL;
    }
    fprintf(stderr, "RSP: syntax error: ");
    bytes_fprintln_chr(line, stderr);
    return RSPToken_SYNTAX_ERR;
}

static bool rsp_loop(RSP *ctx)
{
    bool is_ok;
    do
    {
        switch (rsp_load_line(ctx))
        {
        case RSPToken_EOF:
            return true;
        case RSPToken_TAG:
            is_ok = ctx->core->tag(ctx->core, ctx->var.tag);
            break;
        case RSPToken_KEY_VAL:
            is_ok = ctx->core->key_val(ctx->core, ctx->var.key, ctx->var.val);
            break;
        case RSPToken_NULL:
            is_ok = ctx->core->go(ctx->core);
            break;
        case RSPToken_COMMENT:
            is_ok = true;
            break;
        case RSPToken_SYNTAX_ERR:
            is_ok = false;
            break;
        default:
            exit(1);
        }
    } while (is_ok);
    return false;
}

bool rsp_execute(RSP *ctx, RSPCore *core, const char *filename)
{
    rdr_load(&ctx->rdr, filename);
    ctx->var = rsp_var_null();
    ctx->core = core;
    bool is_ok = rsp_loop(ctx);
    ctx->var = rsp_var_null();
    ctx->core = NULL;
    return is_ok;
}
