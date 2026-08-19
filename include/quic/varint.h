#ifndef QUIC_VARINT_H
#define QUIC_VARINT_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/*
QUIC packets and frames commonly use a variable-length encoding for non-negative 
integer values. This encoding ensures that smaller integer values need fewer bytes 
to encode.

This means that integers are encoded on 1, 2, 4, or 8 bytes and can encode 6-, 14-, 
30-, or 62-bit values, respectively.


2MSB	Length	Usable Bits	    Range
00	    1	    6	            0-63
01	    2	    14	            0-16383
10	    4	    30	            0-1073741823
11	    8	    62	            0-4611686018427387903

https://datatracker.ietf.org/doc/html/rfc9000#name-variable-length-integer-enc

*/

#define QUIC_VARINT_MAX ((uint64_t)0x3FFFFFFFFFFFFFFFULL)

typedef struct {
    const uint8_t *buf;   // start of the buffer
    size_t buf_len;       // total length of the buffer
    size_t pos;           // current read position
    bool error;           // set to true if a read fails (e.g. truncated data)
} quic_cursor_t;

// Initializes a cursor over a buffer, ready for reading.
void quic_cursor_init(quic_cursor_t *cursor, const uint8_t *buf, size_t buf_len);

// Reads one varint from the cursor, advancing its position.
// On failure (not enough bytes remaining), sets cursor->error = true
// and returns 0. Callers should check cursor->error after calling.
uint64_t ReadVarint(quic_cursor_t *cursor);

// Returns the number of bytes needed to encode `value` as a varint
// (1, 2, 4, or 8). Returns 0 if value exceeds QUIC_VARINT_MAX.
size_t quic_varint_len(uint64_t value);

// Writes `value` as a varint into buf (must have at least
// quic_varint_len(value) bytes available).
// Returns bytes written, or 0 on error.
size_t WriteVarint(uint8_t *buf, size_t buf_len, uint64_t value);

#endif