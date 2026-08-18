#ifndef QUIC_UDP_H
#define QUIC_UDP_H

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

typedef struct {
    int fd;
} quic_udp_t;

int quic_udp_init(quic_udp_t *udp, uint16_t port);

int quic_udp_send(
    quic_udp_t *udp,
    const uint8_t *data,
    size_t len,
    const struct sockaddr *dest,
    socklen_t dest_len
);

int quic_udp_recv(
    quic_udp_t *udp,
    uint8_t *buffer,
    size_t buffer_len,
    struct sockaddr *src,
    socklen_t *src_len
);

void quic_udp_close(quic_udp_t *udp);

#endif