#include <stdint.h>
#include <stddef.h>
/*
Long headers are used for packets that are sent prior to the establishment of 1-RTT 
keys. Once 1-RTT keys are available, a sender switches to sending packets using the 
short header (Section 17.3).

-- A 1-RTT packet uses a short packet header. It is used after the version and 1-RTT 
keys are negotiated.

https://datatracker.ietf.org/doc/html/rfc9000#name-long-header-packets

*/

typedef struct {
    uint8_t header_byte;
    uint32_t version;

    uint8_t     dest_conn_id_length;
    uint8_t     dest_conn_id[20];

    uint8_t     source_conn_id_length;
    uint8_t     source_conn_id[20];
}quic_long_header_t;

// Data is pointer to data byte while size of data is not limited 8 bits.
typedef struct{
    uint8_t *data;
    size_t len;

}quic_payload_t;


// Short header contains payload which contains frames.
typedef struct {

    uint8_t header_byte;

    uint8_t dest_conn_id[20];
    uint8_t dest_conn_id_len;

    uint8_t packet_num[4];
    uint8_t packet_num_len;

    quic_payload_t payload;

} quic_short_header_t;




