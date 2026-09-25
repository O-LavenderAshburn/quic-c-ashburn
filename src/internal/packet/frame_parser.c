#include <stdlib.h>

#include "packet.h"
#include "varint.h"


quic_parse_status_t parse_reset_stream_frame() {return QUIC_PARSE_OK;}

quic_parse_status_t parse_stop_sending_frame() {return QUIC_PARSE_OK;}

quic_parse_status_t parse_crypto_frame() {return QUIC_PARSE_OK;}

quic_parse_status_t parse_new_token_frame() {return QUIC_PARSE_OK;}

quic_parse_status_t parse_max_data_frame() {return QUIC_PARSE_OK;}

quic_parse_status_t parse_max_stream_data_frame() {return QUIC_PARSE_OK;}

quic_parse_status_t parse_max_streams_frame() {return QUIC_PARSE_OK;}

quic_parse_status_t parse_data_blocked_frame() {return QUIC_PARSE_OK;}

quic_parse_status_t parse_stream_data_blocked_frame() {return QUIC_PARSE_OK;}

quic_parse_status_t parse_streams_blocked_frame() {return QUIC_PARSE_OK;}

quic_parse_status_t parse_new_conn_id_frame() {return QUIC_PARSE_OK;}

quic_parse_status_t parse_retire_conn_id_frame() {return QUIC_PARSE_OK;}

quic_parse_status_t parse_path_challenge_frame() {return QUIC_PARSE_OK;}

quic_parse_status_t parse_path_response_frame() {return QUIC_PARSE_OK;}

quic_parse_status_t parse_conn_close_frame() {return QUIC_PARSE_OK;}

quic_parse_status_t parse_handshake_done_frame() {return QUIC_PARSE_OK;}

/***
 * 
 * Parse a stream frame.
 * 
 * @param data Payload data.
 * @param len Length of payload data.
 * @param out Frame to produce.
 * @param body_consumed The amount of payload data consumed.
 * @param has_offset If payload has offset field set.
 * @param has_length If payload has length field set.
 * @param has_fin If payload fin field is set.
 * 
 * @return Parse status.
 *  
 */
quic_parse_status_t parse_stream_frame(
    const uint8_t *data, size_t len, quic_stream_frame_t *out, size_t *body_consumed,
    bool has_offset, bool has_length, bool has_fin)
{
    quic_cursor_t cursor;
    quic_cursor_init(&cursor, data,len);
    out->stream_id = ReadVarint(&cursor);
                                            
    if(cursor.error) return QUIC_PARSE_ERR_TRUNCATED;

    if(has_offset){
        out->offset = ReadVarint(&cursor);
        if(cursor.error) return QUIC_PARSE_ERR_TRUNCATED;

    }else{
        out->offset = 0;
    }

    if(has_length){
        out->length = ReadVarint(&cursor);
        if(cursor.error) return QUIC_PARSE_ERR_TRUNCATED;
    }else{
        out->length = len - cursor.pos;
    }

    // Make sure the declared length doesn't run past what we actually have
    if (cursor.pos + out->length > len) {
        return QUIC_PARSE_ERR_TRUNCATED;
    }

    out->data = (uint8_t *) &data[cursor.pos];
    *body_consumed += cursor.pos;
    out->fin = has_fin;

    return QUIC_PARSE_OK;

}

quic_parse_status_t parse_ack_frame( 
    const uint8_t *data, size_t len, quic_ack_frame_t  *out,  size_t *body_consumed,
    bool has_ecn) 
{
    quic_cursor_t cursor;
    quic_cursor_init(&cursor,data,len);

    out->ack_ranges = NULL;
    out->ecn_counts = (quic_ecn_counts_t){0};



    out->largest_acknowledged = ReadVarint(&cursor);
    if(cursor.error) return QUIC_PARSE_ERR_TRUNCATED;

    out->ack_delay = ReadVarint(&cursor);
    if(cursor.error) return QUIC_PARSE_ERR_TRUNCATED;

    out->ack_range_count = ReadVarint(&cursor);
    if(cursor.error) return QUIC_PARSE_ERR_TRUNCATED;

    out->first_ack_range = ReadVarint(&cursor);
    if(cursor.error) return QUIC_PARSE_ERR_TRUNCATED;

    if(out->ack_range_count > 0){
        out->ack_ranges = calloc(out->ack_range_count,sizeof(quic_ack_range_t));
        if (!out->ack_ranges) return QUIC_PARSE_ERR_TRUNCATED;

        for(uint64_t i = 0; i < out->ack_range_count;i++){
            out->ack_ranges[i].gap = ReadVarint(&cursor);

            if (cursor.error) {
                free(out->ack_ranges);
                out->ack_ranges = NULL;
                return QUIC_PARSE_ERR_TRUNCATED;
            }

            out->ack_ranges[i].ack_range_length = ReadVarint(&cursor);

            if (cursor.error) {
                free(out->ack_ranges);
                out->ack_ranges = NULL;
                return QUIC_PARSE_ERR_TRUNCATED;
            }
        }
    }

    if (has_ecn){
        out->ecn_counts.ect0_count = ReadVarint(&cursor);
        if (cursor.error) return QUIC_PARSE_ERR_TRUNCATED;

        out->ecn_counts.ect1_count = ReadVarint(&cursor);
        if (cursor.error) return QUIC_PARSE_ERR_TRUNCATED;

        out->ecn_counts.ecn_ce_count = ReadVarint(&cursor);
        if (cursor.error) return QUIC_PARSE_ERR_TRUNCATED;
    }

    *body_consumed += cursor.pos;
    return QUIC_PARSE_OK;

}

/**
 * 
 * Decide what the current frame from the data is and process it based on type
 * in frame type field.
 * 
 * @param consumed the amount of the the payload consumed 
 * @param out quic frame to return
 * @param len leng;th of the data
 * @param data data from the wire
 * 
 * @return parse result including packet.
 */
quic_frame_parse_result_t quic_parse_frame(const uint8_t *data, size_t len,
                                           quic_frame_t *out, size_t *consumed)
{

    uint64_t frame_type;
    size_t type_len;
    quic_cursor_t cursor;

    quic_cursor_init(&cursor, data, len);
    frame_type = ReadVarint(&cursor);
    if (cursor.error)
    {
        return (quic_frame_parse_result_t){.status = QUIC_PARSE_INCOMPLETE};
    }
    quic_parse_status_t parse_status;
    type_len = cursor.pos;
    const uint8_t *rest = data + type_len;
    size_t rest_len = len - type_len;
    size_t body_consumed = 0;

    out->type = frame_type;

    // Parse Ack or Stream frame
    if (frame_type >= 0x08 && frame_type <= 0x0F)
    {
        // Check if fields are present
        bool has_offset = frame_type & 0x04;
        bool has_len = frame_type & 0x02;
        bool has_fin = frame_type & 0x01;
        parse_status = parse_stream_frame(rest, rest_len, &out->stream,
                                          &body_consumed, has_offset, has_len, has_fin);
    }

    else if (frame_type == 0x02 || frame_type == 0x03)
    {
        bool has_ecn = false;
        if(frame_type == 0x03){
            has_ecn = true;
        }
        parse_status = parse_ack_frame(rest,rest_len,&out,body_consumed,has_ecn);
    }

    else if (frame_type == 0x16 || frame_type == 0x17)
    {
        parse_status = parse_streams_blocked_frame();
    }
    else
    {

        switch (frame_type)
        {
        // Padding and ping frames.
        case 0x00:
        case 0x01:
            parse_status = QUIC_PARSE_OK;
            body_consumed = 0;
            break;

        // Reset and stop frames.
        case 0x04:
            parse_status = parse_reset_stream_frame();
            break;

        case 0x05:
            parse_status = parse_stop_sending_frame();
            break;
        // Crypto frames.
        case 0x06:
            parse_status = parse_crypto_frame();
            break;

        case 0x07:
            parse_status = parse_new_token_frame();
            break;
        // Data limit frames.
        case 0x10:
            parse_status = parse_max_data_frame();
            break;

        case 0x11:
            parse_status = parse_max_stream_data_frame();
            break;

        case 0x14:
            parse_status = parse_data_blocked_frame();
            break;
        case 0x15:
            parse_status = parse_stream_data_blocked_frame();
        break;
        // Connection ID frames.
        case 0x18:
            parse_status = parse_new_conn_id_frame();
            break;

        case 0x19:
            parse_status = parse_retire_conn_id_frame();
            break;

        // Path handshake frames
        case 0x1a:
            parse_status = parse_path_challenge_frame();
            break;

        case 0x1b:
            parse_status = parse_path_response_frame();
            break;
        case 0x1e:
            parse_status = parse_handshake_done_frame();
            break;

        // Connection close frames.
        case 0x1c:
        case 0x1d:
            parse_status = parse_conn_close_frame();
            break;

        default:
            parse_status = QUIC_PARSE_ERR_PROTOCOL; 
            break;
        }
    }

    *consumed = type_len + body_consumed;
    return (quic_frame_parse_result_t){ .status = parse_status, .frame = *out };

}



