#ifndef QUIC_PACKET_H
#define QUIC_PACKET_H

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

/*
 * Raw packet payload represented as a pointer to an array of bytes.
 * `len` specifies the number of bytes in the payload.
 */
typedef struct {
    uint8_t *data;
    size_t   len;
} quic_payload_t;


// Short header contains payload which contains frames.
typedef struct {

    uint8_t header_byte;

    uint8_t dest_conn_id[20];
    uint8_t dest_conn_id_len;

    uint8_t packet_num[4];
    uint8_t packet_num_len;

    quic_payload_t payload;

} quic_short_header_t;


typedef struct {
    uint64_t    largest_acknowledged;
    uint64_t    ack_delay;
    uint64_t    ack_range_count;
    uint64_t    first_ack_range;
} quic_ack_frame_t;

typedef struct{
    uint64_t    stream_id;
    uint16_t    application_protocol_error_code;       
    uint64_t    final_size;
}quic_rst_stream_frame_t;

typedef struct{
     uint64_t   stream_id;
     uint16_t   application_protocol_error_code;  
}quic_stop_stream_t;

typedef struct {
    uint64_t    offset;
    uint64_t    length;
    uint8_t     *data;
}quic_crypto_frame_t;

typedef struct{
    uint64_t    token_length;
    uint8_t     *data;
}quic_new_token_frame_t;

typedef struct {
    uint64_t stream_id;
    uint64_t offset;
    uint64_t length;
    uint8_t *data;
} quic_stream_frame_t;

typedef struct {
    uint64_t    max_data;
}quic_max_data_frame_t;

typedef struct {
    uint64_t    stream_id;
    uint64_t    max_data;
}quic_max_stream_data_frame_t;

typedef struct {
    uint64_t    max_streams;
}quic_max_streams_frame_t;

typedef struct {
    uint64_t    max_data;
}quic_data_blocked_frame_t;

typedef struct {
    uint64_t max_streams;
}quic_streams_blocked_t;

typedef struct {
    uint64_t    sequence_num;
    uint64_t    retire_prior_to;
    uint8_t     length;
    uint8_t     conn_id[20];
    uint16_t    statless_rst_token;
}quic_new_conn_id_t;

typedef struct {
    uint64_t    sequence_num;
}quic_retire_conn_id_frame_t;

typedef struct {
    uint64_t data;
}quic_path_challenge_frame_t;

typedef struct {
    uint64_t data;
}quic_path_response_frame_t;

typedef struct {
    uint64_t    error_code;
    uint64_t    frame_type;
    uint64_t    reason_phrase_len;
    uint8_t     *data;
}quic_conn_close_frame_t;

typedef struct {
    // Type only frames are [PADDING, PING, HANDSHAKE_DONE].
    uint8_t type;
    union {
        quic_ack_frame_t                ack;
        quic_rst_stream_frame_t         stream_rst;
        quic_stop_stream_t              stream_stop;
        quic_stream_frame_t             max_stream;
        quic_new_token_frame_t          new_token;
        quic_crypto_frame_t             crypto;
        quic_max_data_frame_t           max_data;
        quic_max_stream_data_frame_t    max_stream_data;
        quic_max_streams_frame_t        max_streams;
        quic_streams_blocked_t          stream_blocked;
        quic_data_blocked_frame_t       data_blocked;
        quic_new_conn_id_t              new_conn_id;
        quic_retire_conn_id_frame_t     retire_conn_id;
        quic_path_challenge_frame_t     path_challenge;
        quic_path_response_frame_t      path_challenge_response;
        quic_conn_close_frame_t         conn_close;
    };
} quic_frame_t;



#endif