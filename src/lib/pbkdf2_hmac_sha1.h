#ifndef PBKDF2_H_FCC04BD9B2270C0C
#define PBKDF2_H_FCC04BD9B2270C0C

#include <stdbool.h>
#include <stdint.h>

#include "hmac_sha1.h"

// PBKDF2 (P, S, c, dkLen)
bool pbkdf2_hmac_sha1(const uint8_t *p, uint32_t p_len,
                      const uint8_t *s, uint32_t s_len,
                      uint64_t c,
                      uint32_t dk_len,
                      uint8_t *dk);

#endif
