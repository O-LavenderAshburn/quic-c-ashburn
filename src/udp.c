#include "quic/udp.h"

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

/*
 * Create and bind a UDP socket.
 *
 * The file descriptor returned by socket() identifies the socket
 * and is stored in the quic_udp_t structure for later operations.
 */
int quic_udp_init(quic_udp_t *udp, uint16_t port)
{
    udp->fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (udp->fd < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_in addr = {0};

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    // Bind socket to requested local port
    if (bind(udp->fd,
             (struct sockaddr *)&addr,
             sizeof(addr)) < 0) {
        perror("bind");
        close(udp->fd);
        udp->fd = -1;
        return -1;
    }

    printf("UDP socket fd=%d bound to port %u\n", udp->fd, port);

    return 0;
}

int quic_udp_send(
    quic_udp_t *udp,
    const uint8_t *data,
    size_t  len,
    const struct sockaddr *dest,
    socklen_t dest_len){

    return sendto(
        udp->fd,
        data,
        len,
        0,
        dest,
        dest_len
    );
}

int quic_udp_recv(
    quic_udp_t *udp,
    uint8_t *buffer,
    size_t buffer_len,
    struct sockaddr *src,
    socklen_t *src_len){

    return recvfrom(
        udp->fd,
        buffer,
        buffer_len,
        0,
        src,
        src_len
    );


}

/*
 * Close the UDP socket and invalidate its file descriptor.
 */
void quic_udp_close(quic_udp_t *udp)
{
    if (udp->fd >= 0) {
        close(udp->fd);
        udp->fd = -1;
    }
}


