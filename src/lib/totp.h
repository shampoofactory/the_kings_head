#ifndef TOTP_H_4E41188CFEC92E10
#define TOTP_H_4E41188CFEC92E10

#include <stdint.h>

uint32_t totp_sha1_gen(HMAC_SHA1_CTX *ctx, uint64_t t);

void totp_code_str(char *dst, uint64_t v, uint32_t n_digits);

#endif
