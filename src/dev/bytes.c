#include "bytes.h"

#include <string.h>

static uint8_t decimal(char c)
{
    static const uint8_t LUT[256] =

        {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
         0x08, 0x09, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    return LUT[(uint8_t)c];
}

static uint8_t nibble(char c)
{
    static const uint8_t LUT[256] =

        {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
         0x08, 0x09, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    return LUT[(uint8_t)c];
}

Bytes bytes_null()
{
    return (Bytes){.ptr = NULL, .len = 0};
}

Bytes bytes_with(uint8_t *ptr, size_t len)
{
    return (Bytes){.ptr = ptr, .len = len};
}

Bytes bytes_str(char *str)
{
    return (Bytes){.ptr = (uint8_t *)str, .len = strlen(str)};
}

Bytes bytes_head(Bytes self, size_t index)
{
    return index <= self.len
               ? (Bytes){.ptr = self.ptr, .len = index}
               : bytes_null();
}

Bytes bytes_tail(Bytes self, size_t index)
{
    return index <= self.len
               ? (Bytes){.ptr = self.ptr + index, .len = self.len - index}
               : bytes_null();
}

size_t bytes_set(Bytes self, uint8_t *src, size_t src_len)
{
    size_t len = src_len < self.len ? src_len : self.len;
    memcpy(self.ptr, src, len);
    return len;
}

size_t bytes_get(Bytes self, uint8_t *dst, size_t dst_len)
{
    size_t len = dst_len < self.len ? dst_len : self.len;
    memcpy(dst, self.ptr, len);
    return len;
}

bool bytes_is_null(Bytes self)
{
    return self.ptr == NULL && self.len == 0;
}

bool bytes_equal(Bytes self, Bytes other)
{
    return other.len == self.len && memcmp(other.ptr, self.ptr, self.len) == 0;
}

bool bytes_equal_string(Bytes self, const char *string)
{
    size_t string_len = strlen(string);
    return string_len == self.len && memcmp(string, self.ptr, self.len) == 0;
}

bool bytes_to_string(Bytes self, char *string, size_t len)
{
    if (len <= self.len)
    {
        return false;
    }
    memcpy(string, self.ptr, self.len);
    *(string + self.len) = 0;
    return true;
}

bool bytes_to_hex_string(Bytes self, char *string, size_t len)
{
    if (len <= 3 + self.len * 2)
    {
        return false;
    }
    sprintf(string, "0x");
    for (size_t i = 0; i < self.len; i++)
    {
        sprintf(string + 2 + 2 * i, "%02X", *(self.ptr + i));
    }
    *(string + 2 + self.len * 2) = 0;
    return true;
}

void bytes_trim(Bytes *self)
{
    uint8_t *head = self->ptr;
    uint8_t *tail = self->ptr + self->len;
    while ((head != tail) && (*head == ' '))
    {
        head++;
    }
    while ((tail != head) && (*(tail - 1) == ' '))
    {
        tail--;
    }
    self->ptr = head;
    self->len = tail - head;
}

void bytes_fprint_chr(Bytes self, FILE *file)
{
    for (size_t i = 0; i < self.len; i++)
    {
        fprintf(file, "%c", *(self.ptr + i));
    }
}

void bytes_fprintln_chr(Bytes self, FILE *file)
{
    bytes_fprint_chr(self, file);
    fprintf(file, "\n");
}

void bytes_print_chr(Bytes self)
{
    bytes_fprint_chr(self, stdout);
}

void bytes_println_chr(Bytes self)
{
    bytes_fprint_chr(self, stdout);
}

void bytes_fprint_hex(Bytes self, FILE *file)
{
    for (size_t i = 0; i < self.len; i++)
    {
        fprintf(file, "%02x", *(self.ptr + i));
    }
}

void bytes_fprintln_hex(Bytes self, FILE *file)
{
    bytes_fprint_hex(self, file);
    fprintf(file, "\n");
}

void bytes_print_hex(Bytes self)
{
    bytes_fprint_hex(self, stdout);
}

void bytes_println_hex(Bytes self)
{
    bytes_fprintln_hex(self, stdout);
}

bool bytes_parse_hex(Bytes self, Bytes *dst)
{
    if (self.len % 2 != 0 || dst->len < self.len / 2)
    {
        return false;
    }
    int8_t u = 0;
    int8_t v = 0;
    for (size_t i = 0; i < self.len / 2; i++)
    {
        uint8_t x = nibble(*(self.ptr + i * 2));
        uint8_t y = nibble(*(self.ptr + i * 2 + 1));
        u |= (int8_t)x;
        v |= (int8_t)y;
        *(dst->ptr + i) = x * 16 + y;
    }
    dst->len = self.len / 2;
    return (u | v) >= 0;
}

bool bytes_parse_uint64(Bytes self, uint64_t *dst)
{
    if (self.len == 0)
    {
        return false;
    }
    int64_t v = 0;
    int64_t m = 1;
    int8_t u = 0;
    size_t i = self.len;
    do
    {
        uint8_t x = decimal(*(self.ptr + --i));
        v += m * x;
        u |= (int8_t)x;
        m *= 10;
    } while (i != 0);
    *dst = v;
    return u >= 0;
}

bool bytes_starts_with(Bytes self, uint8_t byte)
{
    return self.len != 0 && *self.ptr == byte;
}

bool bytes_ends_with(Bytes self, uint8_t byte)
{
    return self.len != 0 && *(self.ptr + self.len - 1) == byte;
}

size_t bytes_index_of(Bytes self, uint8_t byte)
{
    uint8_t *eq = memchr(self.ptr, byte, self.len);
    return eq != NULL ? eq - self.ptr : -1;
}