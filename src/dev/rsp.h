#ifndef RSP_5CFF26675C545340
#define RSP_5CFF26675C545340

#include <stddef.h>
#include <stdint.h>

#include "rdr.h"
#include "bytes.h"

typedef enum
{
    RSPToken_EOF = 0x00,
    RSPToken_NULL = 0x10,
    RSPToken_TAG = 0x11,
    RSPToken_KEY_VAL = 0x12,
    RSPToken_COMMENT = 0x13,
    RSPToken_SYNTAX_ERR = 0x80,
} RSPToken;

typedef struct RSPCore RSPCore;

struct RSPCore
{
    bool (*tag)(RSPCore *ctx, Bytes tag);
    bool (*key_val)(RSPCore *ctx, Bytes key, Bytes val);
    bool (*go)(RSPCore *ctx);
};

RSPCore rsp_core_null();

typedef struct
{
    Bytes tag;
    Bytes key;
    Bytes val;
    Bytes comment;
} RSPVar;

RSPVar rsp_var_null();

typedef struct
{
    Rdr rdr;
    RSPCore *core;
    RSPVar var;
} RSP;

RSP rsp_create(size_t rdr_len);

void rsp_destroy(RSP *ctx);

bool rsp_execute(RSP *ctx, RSPCore *core, const char *filename);

#endif
