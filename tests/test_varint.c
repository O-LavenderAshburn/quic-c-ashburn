#include <assert.h>
#include <stdio.h>
#include "quic/varint.h"

static void test_roundtrip(uint64_t original) {
    uint8_t buf[8];
    size_t written = WriteVarint(buf, sizeof(buf), original);
    assert(written > 0); // should always succeed for valid values

    quic_cursor_t cursor;
    quic_cursor_init(&cursor, buf, written);
    uint64_t decoded = ReadVarint(&cursor);

    assert(decoded == original);
    assert(!cursor.error);
    assert(cursor.pos == written);

    printf("PASS: value=%llu, bytes=%zu\n",
           (unsigned long long)original, written);
}

int main(void) {
    // small values (1-byte range)
    test_roundtrip(0);
    test_roundtrip(1);
    test_roundtrip(32);
    test_roundtrip(63);

    // 1-byte/2-byte boundary
    test_roundtrip(64);
    
    test_roundtrip(15293);
    test_roundtrip(16383);

    // 2-byte/4-byte boundary
    test_roundtrip(16384);
    test_roundtrip(1000000);
    test_roundtrip(1073741823);

    // 4-byte/8-byte boundary
    test_roundtrip(1073741824);
    test_roundtrip(151288809941952652ULL); // RFC 9000 example value
    test_roundtrip(QUIC_VARINT_MAX);

    printf("\nAll tests passed!\n");
    return 0;
}