/*
 * send-frames: sends the Ethernet frames of a file out of one interface.
 *
 * Usage: send-frames IFNAME FILE
 *
 * FILE holds frames as a 2-byte big-endian length followed by that many bytes,
 * as tools/vm-test/frames.py writes them. Built with the OpenWrt SDK toolchain
 * so the test VM needs no Python or packet tools.
 */
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    struct sockaddr_ll address;
    unsigned char frame[2048];
    unsigned char length_bytes[2];
    unsigned int sent = 0;
    FILE *input;
    int fd;

    if (argc != 3) {
        fprintf(stderr, "usage: %s IFNAME FILE\n", argv[0]);
        return 1;
    }
    memset(&address, 0, sizeof(address));
    address.sll_family = AF_PACKET;
    address.sll_ifindex = (int)if_nametoindex(argv[1]);
    address.sll_halen = 6;
    if (address.sll_ifindex == 0) {
        perror(argv[1]);
        return 1;
    }
    input = fopen(argv[2], "rb");
    if (input == NULL) {
        perror(argv[2]);
        return 1;
    }
    fd = socket(AF_PACKET, SOCK_RAW, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }
    while (fread(length_bytes, 1, sizeof(length_bytes), input) == sizeof(length_bytes)) {
        const size_t length = (size_t)length_bytes[0] << 8 | length_bytes[1];

        if (length > sizeof(frame) || fread(frame, 1, length, input) != length) {
            fprintf(stderr, "%s: truncated frame %u\n", argv[2], sent);
            return 1;
        }
        memcpy(address.sll_addr, frame, 6);
        if (sendto(fd, frame, length, 0, (struct sockaddr *)&address, sizeof(address)) < 0) {
            perror("sendto");
            return 1;
        }
        sent++;
    }
    printf("sent %u frames on %s\n", sent, argv[1]);
    return 0;
}
