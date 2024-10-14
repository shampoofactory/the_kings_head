#ifndef SHA1_H_982988038BDE4D84
#define SHA1_H_982988038BDE4D84

#include <stdint.h>

void sha1_digest(uint8_t md[static 20], const uint8_t *m, uint32_t m_len);

void sha1_final(uint8_t md[static 20], const uint8_t *restrict m, uint8_t *restrict blk, uint32_t m_len);

void sha1_init(uint8_t hash[static 20]);

void sha1_transform(uint8_t hash[static 20], const uint8_t *blk, int32_t n_blk);

#endif
