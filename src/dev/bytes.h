#ifndef BYTES_H_B2C9890FCFF5A808
#define BYTES_H_B2C9890FCFF5A808

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

// Bytes reference.
typedef struct
{
    uint8_t *ptr;
    size_t len;
} Bytes;

Bytes bytes_null();

Bytes bytes_with(uint8_t *ptr, size_t len);

Bytes bytes_str(char *str);

Bytes bytes_head(Bytes self, size_t index);

Bytes bytes_tail(Bytes self, size_t index);

size_t bytes_set(Bytes self, uint8_t *src, size_t src_len);

size_t bytes_get(Bytes self, uint8_t *dst, size_t dst_len);

bool bytes_is_null(Bytes self);

bool bytes_equal(Bytes self, Bytes other);

bool bytes_equal_string(Bytes self, const char *string);

bool bytes_to_string(Bytes self, char *string, size_t len);

bool bytes_to_hex_string(Bytes self, char *string, size_t len);

void bytes_trim(Bytes *self);

void bytes_fprint_chr(Bytes self, FILE *file);

void bytes_fprintln_chr(Bytes self, FILE *file);

void bytes_print_chr(Bytes self);

void bytes_println_chr(Bytes self);

void bytes_fprint_hex(Bytes self, FILE *file);

void bytes_fprintln_hex(Bytes self, FILE *file);

void bytes_print_hex(Bytes self);

void bytes_println_hex(Bytes self);

// Hex string to hex ptr.
// 'self.len' must be of even length.
// 'dst' must be of sufficient length: 'src_len / 2'.
// Return true on success, false on invalid lengths or non-hex characters.
bool bytes_parse_hex(Bytes self, Bytes *dst);

// Decimal string to unsigned integer.
// Return true on success, false otherwise.
bool bytes_parse_uint64(Bytes self, uint64_t *dst);

bool bytes_starts_with(Bytes self, uint8_t byte);

bool bytes_ends_with(Bytes self, uint8_t byte);

// Returns first index of 'byte' or -1 if not found.
size_t bytes_index_of(Bytes self, uint8_t byte);

#endif
