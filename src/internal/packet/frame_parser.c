#include "packet.h"
#include "varint.h"


quic_frame_parse_result_t quic_parse_frame(const uint8_t *data, size_t len,
                                       quic_frame_t *out, size_t *consumed){

    uint64_t frame_type;
    size_t type_len;
    quic_cursor_t cursor;

    quic_cursor_init(&cursor,data,len);
    frame_type = ReadVarint(&cursor);
    if (cursor.error) {
        return (quic_frame_parse_result_t){ .status = QUIC_PARSE_INCOMPLETE };
    }
    quic_parse_status_t parse_status;
    type_len = cursor.pos;
    const uint8_t *rest = data + type_len;
    size_t rest_len = len- type_len;
    size_t body_consumed = 0;
    
    out->type = frame_type;

    // Parse Ack or Stream frame
    if(frame_type >= 0x08 && frame_type <= 0x0F){
        parse_status = parse_stream();
    }else if(frame_type == 0x02 || frame_type == 0x03){
        parse_status = parse_ack();
    }else if(frame_type == 0x16 || frame_type == 0x17){
        parse_status = parse_streams_blocked();

    }else{

        switch (frame_type)
        {
        case 0x00:  // PADDING
        case 0x01:  // PING
            parse_status = QUIC_PARSE_OK;
            body_consumed = 0;
            break;

        case 0x04:
            parse_status = parse_reset_stream();
            break;

        case 0x05:
            parse_status = parse_stop_sending();
            break;

        case 0x06:
            parse_status = parse_crypto();
            break;

        case 0x07:
            parse_status = parse_new_token();
            break;

        case 0x10:
            parse_status = parse_max_data();
            break;
            
        case 0x11:
            parse_status = parse_max_stream_data();
            break;
        
        case 0x14:
            parse_status = parse_data_blocked();
            break;
        case 0x15:
            parse_status = parse_stream_data_blocked();
            break;

        case 0x18:
            parse_status = parse_new_conn_id();
            break;

        case 0x19:
            parse_status = parse_retire_conn_id();
            break;
        
        case 0x1a: 
            parse_status = parse_path_challenge();
            break;
            
        case 0x1b:
            parse_status = parse_path_response();
            break;

        case 0x1e:
            parse_status = parse_handshake_done();
            break;

        case 0x1c:
        case 0x1d:
            parse_status = parse_conn_close();
            break;

        default:
            parse_status = QUIC_PARSE_ERR_PROTOCOL;
            break;
        }

    }
    
}


quic_parse_status_t parse_stream(){}

quic_parse_status_t parse_ack(){}

quic_parse_status_t parse_reset_stream(){}

quic_parse_status_t parse_stop_sending(){}

quic_parse_status_t parse_crypto(){}

quic_parse_status_t parse_new_token(){}

quic_parse_status_t parse_max_data(){}

quic_parse_status_t parse_max_stream_data(){}

quic_parse_status_t parse_max_streams(){}

quic_parse_status_t parse_data_blocked(){}

quic_parse_status_t parse_stream_data_blocked(){}

quic_parse_status_t parse_streams_blocked(){}

quic_parse_status_t parse_new_conn_id(){}

quic_parse_status_t parse_retire_conn_id(){}

quic_parse_status_t parse_path_challenge(){}

quic_parse_status_t parse_path_response(){}

quic_parse_status_t parse_conn_close(){}

quic_parse_status_t parse_handshake_done(){}




