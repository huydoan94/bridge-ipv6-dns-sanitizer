#include "packet.h"

#include <climits>
#include <cstring>

#include <tins/constants.h>
#include <tins/endianness.h>
#include <tins/ipv6_address.h>
#include <tins/utils/checksum_utils.h>

constexpr unsigned int IPV6_WIRE_VERSION = 6U;
constexpr unsigned int IPV6_VERSION_FIELD_BITS = 4U;

uint16_t read_be16(const uint8_t *p)
{
    uint16_t network_value;

    std::memcpy(&network_value, p, sizeof(network_value));
    return Tins::Endian::be_to_host(network_value);
}

static bool has_ipv6_version(const uint8_t *packet)
{
    const unsigned int version_shift = CHAR_BIT - IPV6_VERSION_FIELD_BITS;

    return (packet[0] >> version_shift) == IPV6_WIRE_VERSION;
}

enum ipv6_packet_result parse_nfqueue_ipv6_payload(
    uint8_t *payload,
    size_t payload_len,
    struct ipv6_packet_view *view
)
{
    const size_t ipv6_payload_len_offset = offsetof(struct ip6_hdr, ip6_plen);
    uint16_t ipv6_payload_len;
    size_t ipv6_packet_len;

    if (
        payload == nullptr ||
        view == nullptr ||
        payload_len < sizeof(struct ip6_hdr) ||
        !has_ipv6_version(payload)
    ) {
        return IPV6_PACKET_PASSTHROUGH;
    }

    ipv6_payload_len = read_be16(payload + ipv6_payload_len_offset);
    if (ipv6_payload_len == 0) {
        return IPV6_PACKET_PASSTHROUGH;
    }

    ipv6_packet_len = sizeof(struct ip6_hdr) + ipv6_payload_len;
    if (ipv6_packet_len > payload_len) {
        return IPV6_PACKET_TRUNCATED;
    }

    view->data = payload;
    view->header = reinterpret_cast<struct ip6_hdr *>(payload);
    view->declared_len = ipv6_packet_len;
    view->captured_len = payload_len;
    view->declared_end = payload + ipv6_packet_len;
    view->captured_end = payload + payload_len;
    view->capacity_end = view->captured_end;
    return IPV6_PACKET_OK;
}


int ipv6_packet_replace(
    struct ipv6_packet_view *packet,
    uint8_t *start,
    size_t old_len,
    const std::vector<uint8_t>& replacement
)
{
    if (
        start < packet->data + sizeof(struct ip6_hdr) ||
        start > packet->declared_end ||
        old_len > static_cast<size_t>(packet->declared_end - start)
    ) {
        return -1;
    }

    const size_t payload_len = Tins::Endian::be_to_host(packet->header->ip6_plen);
    if (old_len > payload_len || replacement.size() > UINT16_MAX - (payload_len - old_len)) {
        return -1;
    }
    const size_t captured_len = packet->captured_len - old_len + replacement.size();
    if (captured_len > static_cast<size_t>(packet->capacity_end - packet->data)) {
        return -1;
    }

    // Preserve bytes beyond both the transport and IPv6 declared boundaries.
    std::memmove(
        start + replacement.size(),
        start + old_len,
        static_cast<size_t>(packet->captured_end - (start + old_len))
    );
    if (!replacement.empty()) {
        std::memcpy(start, replacement.data(), replacement.size());
    }

    packet->captured_len = captured_len;
    packet->declared_len = packet->declared_len - old_len + replacement.size();
    packet->captured_end = packet->data + packet->captured_len;
    packet->declared_end = packet->data + packet->declared_len;
    packet->header->ip6_plen = Tins::Endian::host_to_be(
        static_cast<uint16_t>(payload_len - old_len + replacement.size())
    );
    return 0;
}

static uint16_t ipv6_upperlayer_checksum(
    const struct ip6_hdr *ip6h,
    uint16_t protocol,
    const uint8_t *data,
    size_t data_len
)
{
    uint32_t sum = Tins::Utils::pseudoheader_checksum(
        Tins::IPv6Address(ip6h->ip6_src.s6_addr),
        Tins::IPv6Address(ip6h->ip6_dst.s6_addr),
        static_cast<uint16_t>(data_len),
        protocol
    );

    sum += Tins::Utils::sum_range(data, data + data_len);
    while (sum >> 16U) {
        sum = (sum & UINT16_MAX) + (sum >> 16U);
    }

    return Tins::Endian::be_to_host(static_cast<uint16_t>(~sum));
}

uint16_t icmpv6_checksum(
    const struct ip6_hdr *ip6h,
    const uint8_t *icmp,
    size_t icmp_len
)
{
    return ipv6_upperlayer_checksum(
        ip6h,
        Tins::Constants::IP::PROTO_ICMPV6,
        icmp,
        icmp_len
    );
}

uint16_t udp_ipv6_checksum(
    const struct ip6_hdr *ip6h,
    const uint8_t *udp,
    size_t udp_len
)
{
    return ipv6_upperlayer_checksum(
        ip6h,
        Tins::Constants::IP::PROTO_UDP,
        udp,
        udp_len
    );
}
