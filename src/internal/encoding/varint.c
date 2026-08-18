#include "quic/varomt.h"


void quic_cursor_init(quic_cursor_t *cursor, const uint8_t *buf, size_t buf_len){
    cursor->buf = buf;
    cursor->buf_len = buf_len;
    cursor->pos = 0;
    cursor->error = false;
}

uint64_t ReadVarint(quic_cursor_t *cursor){
    //Error check cursosr pos is not over length 
    if(cursosr->pos >= cursor->buf_len){
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

}

size_t WriteVarint(uint8_t *buf, size_t buf_len, uint64_t value){

}
