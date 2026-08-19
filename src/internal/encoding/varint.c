#include "quic/varint.h"


void quic_cursor_init(quic_cursor_t *cursor, const uint8_t *buf, size_t buf_len){
    cursor->buf = buf;
    cursor->buf_len = buf_len;
    cursor->pos = 0;
    cursor->error = false;
}

uint64_t ReadVarint(quic_cursor_t *cursor){
    //Error check cursor pos is not over length 
    if(cursor->pos >= cursor->buf_len){
        cursor->error = true;
        return 0;
    }

    uint8_t first = cursor->buf[cursor->pos];
    uint8_t prefix = first >> 6;
    size_t length = (size_t)1 << prefix;

    if(cursor->pos + length > cursor->buf_len){
        cursor->error = true;
        return 0;
    }

    //Mask top two bits (the length prefix)
    uint64_t value = first & 0x3F;
    
    for (size_t i = 1; i < length; i++ ){
        value = (value << 8) | cursor->buf[cursor->pos + i];
    }

    cursor->pos += length;
    return value;

}

size_t quic_varint_len(uint64_t value){
    if(value <= 0x3F ) return 1;
    if(value <= 0x3FFF ) return 2;
    if(value <= 0x3FFFFFFF ) return 4;
    if(value <= QUIC_VARINT_MAX) return 8;
    return 0;
}

size_t WriteVarint(uint8_t *buf, size_t buf_len, uint64_t value) {
    size_t length = quic_varint_len(value);

    if (length == 0 || buf_len < length) {
        return 0;  // value too large, or not enough room in buf
    }

<<<<<<< HEAD

    // Writes `value` as big-endian bytes into buf, with the 2-bit length
    // marker (00/01/10/11) packed into the top of buf[0].
=======
>>>>>>> 10d026d (quic/varint: Tested varint.)
    switch (length) {
        case 1:
            buf[0] = (uint8_t)value;
            break;
        case 2:
            buf[0] = 0x40 | (uint8_t)(value >> 8);
            buf[1] = (uint8_t)value;
            break;
        case 4:
            buf[0] = 0x80 | (uint8_t)(value >> 24);
            buf[1] = (uint8_t)(value >> 16);
            buf[2] = (uint8_t)(value >> 8);
            buf[3] = (uint8_t)value;
            break;
        case 8:
            buf[0] = 0xC0 | (uint8_t)(value >> 56);
            buf[1] = (uint8_t)(value >> 48);
            buf[2] = (uint8_t)(value >> 40);
            buf[3] = (uint8_t)(value >> 32);
            buf[4] = (uint8_t)(value >> 24);
            buf[5] = (uint8_t)(value >> 16);
            buf[6] = (uint8_t)(value >> 8);
            buf[7] = (uint8_t)value;
            break;
    }

    return length;
}

