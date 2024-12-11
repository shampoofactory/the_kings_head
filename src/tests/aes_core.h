#ifndef AES_CORE_H_8052DB0A5DB6B57A
#define AES_CORE_H_8052DB0A5DB6B57A

#include "bytes.h"
#include "rsp.h"

typedef struct AESCore AESCore;

struct AESCore
{
    RSPCore core;
    bool is_set;
    bool is_encrypt;
    uint8_t *byte_store;
    uint64_t count;
    Bytes key;
    Bytes iv;
    Bytes plaintext;
    Bytes ciphertext;
    Bytes outtext;
};

AESCore aes_core_256_ofb_create();

void aes_core_destroy(AESCore *ctx);

#endif
