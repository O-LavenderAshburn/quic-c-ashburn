#include "quic/udp.h"

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>

int main(void)
{
    quic_udp_t udp;

    if (quic_udp_init(&udp, 4444) != 0) {
        fprintf(stderr, "Failed to initialise UDP\n");
        return 1;
    }

    printf("UDP socket fd=%d bound to port 4444\n", udp.fd);
    printf("Listening on UDP port 4444...\n");

    uint8_t buffer[1024];

    struct sockaddr_in client = {0};
    socklen_t client_len = sizeof(client);

    printf("Waiting for UDP packet...\n");
    fflush(stdout);

    int received = quic_udp_recv(
        &udp,
        buffer,
        sizeof(buffer),
        (struct sockaddr *)&client,
        &client_len
    );

    printf("recvfrom returned: %d\n", received);

    if (received < 0) {
        perror("recvfrom");
        quic_udp_close(&udp);
        return 1;
    }

    printf(
        "Received %d bytes from %s:%d\n",
        received,
        inet_ntoa(client.sin_addr),
        ntohs(client.sin_port)
    );

    printf("Data: ");

    for (int i = 0; i < received; i++) {
        printf("%02x ", buffer[i]);
    }

    printf("\n");

    int sent = quic_udp_send(
        &udp,
        buffer,
        received,
        (struct sockaddr *)&client,
        client_len
    );

    if (sent < 0) {
        perror("sendto");
        quic_udp_close(&udp);
        return 1;
    }

    printf("Echoed %d bytes back.\n", sent);

    quic_udp_close(&udp);

    printf("UDP socket closed.\n");

    return 0;
}