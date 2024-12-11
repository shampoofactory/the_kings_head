#ifndef RDR_H_3BCA0232DF90EB3C
#define RDR_H_3BCA0232DF90EB3C

#include "bytes.h"

typedef struct
{
    uint8_t *head;
    uint8_t *tail;
    uint8_t *pos;
    uint8_t *eol;
    uint8_t *ptr;
    size_t len;
} Rdr;

Rdr rdr_create(size_t len);

void rdr_destroy(Rdr *self);

void rdr_load(Rdr *self, const char *filename);

// Next line
// LF | CRLF terminators.
// Returns bytes references to next line or 'bytes_null' if end of file.
Bytes rdr_next(Rdr *self);

#endif
