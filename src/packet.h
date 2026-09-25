#ifndef BRIDGE_IPV6_DNS_SANITIZER_PACKET_H
#define BRIDGE_IPV6_DNS_SANITIZER_PACKET_H

#include <stddef.h>
#include <stdint.h>
#include <vector>

#include <netinet/in.h>
#include <netinet/ip6.h>

enum ipv6_packet_result {
    IPV6_PACKET_OK = 0,
    IPV6_PACKET_PASSTHROUGH,
    IPV6_PACKET_TRUNCATED,
};

/*
 * NFQUEUE exposes NFQA_PAYLOAD from skb->data. For bridge-family IPv6
 * packets, that starts at the IPv6 header. declared_len follows ip6_plen,
 * while captured_len includes any bytes NFQUEUE supplied after that boundary.
 */
struct ipv6_packet_view {
    uint8_t *data;
    struct ip6_hdr *header;
    uint8_t *declared_end;
    uint8_t *captured_end;
    uint8_t *capacity_end;
    size_t declared_len;
    size_t captured_len;
};


uint16_t read_be16(const uint8_t *p);
enum ipv6_packet_result parse_nfqueue_ipv6_payload(
    uint8_t *payload,
    size_t payload_len,
    struct ipv6_packet_view *view
);
int ipv6_packet_replace(
    struct ipv6_packet_view *packet,
    uint8_t *start,
    size_t old_len,
    const std::vector<uint8_t>& replacement
);


uint16_t icmpv6_checksum(
    const struct ip6_hdr *ip6h,
    const uint8_t *icmp,
    size_t icmp_len
);
uint16_t udp_ipv6_checksum(
    const struct ip6_hdr *ip6h,
    const uint8_t *udp,
    size_t udp_len
);

#endif
