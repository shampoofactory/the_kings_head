#ifndef SHA1_CORE_H_B4627C2EA34B4EF4
#define SHA1_CORE_H_B4627C2EA34B4EF4

#include <stdlib.h>

#include "sha1.h"
#include "bytes.h"
#include "rsp.h"

typedef struct SHA1Core SHA1Core;

struct SHA1Core
{
    RSPCore core;
    bool is_set;
    uint8_t *byte_store;
    uint64_t len;
    Bytes md;
    Bytes msg;
};

SHA1Core sha1_core_create();

void sha1_core_destroy(SHA1Core *ctx);

#endif
