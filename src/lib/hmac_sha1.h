#ifndef HMAC_SHA1_H_5FBA3AB6B63033E4
#define HMAC_SHA1_H_5FBA3AB6B63033E4

#include <stdint.h>

void hmac_sha1(uint8_t hmac[static 20], const uint8_t *k, uint32_t k_len, const uint8_t *m, uint32_t m_len);

#endif
