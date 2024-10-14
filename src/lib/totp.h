#ifndef TOTP_H_4E41188CFEC92E10
#define TOTP_H_4E41188CFEC92E10

#include <stdint.h>

uint64_t totp_div_30(uint64_t ts);

uint64_t totp_div(uint64_t ts, uint32_t s);

void totp_code_str(char *dst, uint64_t v, uint32_t n_digits);

uint32_t totp_sha1_gen(const uint8_t *k, uint32_t k_len, uint64_t t);

#endif
