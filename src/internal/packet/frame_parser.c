#include "packet.h"
#include "varint.h"

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
        parse_status = parse_ack_frame();
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
        case 0x1d:;
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

