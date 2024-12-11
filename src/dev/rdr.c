#include "rdr.h"

#include <stdlib.h>

Rdr rdr_create(size_t len)
{
    uint8_t *ptr = (uint8_t *)malloc(len);
    if (ptr == NULL)
    {
        fprintf(stderr, "Rdr: create: malloc NULL\n");
        exit(1);
    }
    return (Rdr){
        .head = ptr,
        .tail = ptr,
        .pos = ptr,
        .eol = ptr,
        .ptr = ptr,
        .len = len,
    };
}

void rdr_destroy(Rdr *self)
{
    free(self->ptr);
    self->head = NULL;
    self->tail = NULL;
    self->pos = NULL;
    self->eol = NULL;
    self->ptr = NULL;
    self->len = 0;
}

void rdr_load(Rdr *self, const char *filename)
{
    FILE *file = fopen(filename, "r");
    if (file == NULL)
    {
        fprintf(stderr, "Rdr: load: fopen NULL: %s\n", filename);
        exit(1);
    }
    size_t n_bytes = fread(self->ptr, 1, self->len, file);
    fclose(file);
    if (n_bytes == self->len)
    {
        fprintf(stderr, "Rdr: load: fread OVERFLOW: %s\n", filename);
        exit(1);
    }
    self->head = self->ptr;
    self->tail = self->ptr + n_bytes;
    self->pos = self->ptr;
    self->eol = self->ptr;
}

Bytes rdr_next(Rdr *self)
{
    self->head = self->pos;
    if (self->head == self->tail)
    {
        self->eol = self->tail;
        return bytes_null();
    }
    uint8_t old_byte = 0x00;
    while (true)
    {
        if (self->pos == self->tail)
        {
            self->eol = self->pos;
            break;
        }
        uint8_t byte = *self->pos++;
        if (byte == 0x0A)
        {
            if (old_byte == 0x0D)
            {
                self->eol = self->pos - 2;
            }
            else
            {
                self->eol = self->pos - 1;
            }
            break;
        }
        old_byte = byte;
    }
    return bytes_with(self->head, self->eol - self->head);
}
