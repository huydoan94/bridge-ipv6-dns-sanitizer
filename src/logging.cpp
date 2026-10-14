#include "logging.h"

#include "packet.h"

#include <arpa/inet.h>
#include <limits.h>
#include <net/if_arp.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <string>

#include <tins/dhcpv6.h>
#include <tins/hw_address.h>
#include <tins/ipv6_address.h>

constexpr size_t DESTINATION_TEXT_BUFSIZE = INET6_ADDRSTRLEN + sizeof("(all-dhcp-agents)");

static void log_message(FILE *stream, const char *fmt, va_list args)
{
    vfprintf(stream, fmt, args);
    fputc('\n', stream);
    fflush(stream);
}

void log_info(const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    log_message(stdout, fmt, args);
    va_end(args);
}

void log_error(const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    log_message(stderr, fmt, args);
    va_end(args);
}

void set_error(char *buf, size_t len, const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    vsnprintf(buf, len, fmt, args);
    va_end(args);
}

static void format_mac(const uint8_t *mac, char *buf, size_t len)
{
    snprintf(buf, len, "%s", Tins::HWAddress<ETH_ALEN>(mac).to_string().c_str());
}

static void format_ipv6(const struct in6_addr *addr, char *buf, size_t len)
{
    inet_ntop(AF_INET6, addr, buf, static_cast<socklen_t>(len));
}

static void format_destination(const struct in6_addr *addr, char *buf, size_t len)
{
    static const Tins::IPv6Address all_nodes(IPV6_ALL_NODES);
    static const Tins::IPv6Address all_dhcp_agents(IPV6_ALL_DHCP_AGENTS);
    const Tins::IPv6Address destination(addr->s6_addr);
    const std::string ip = destination.to_string();

    if (destination == all_nodes)
        snprintf(buf, len, "%s(all-nodes)", ip.c_str());
    else if (destination == all_dhcp_agents)
        snprintf(buf, len, "%s(all-dhcp-agents)", ip.c_str());
    else
        snprintf(buf, len, "%s", ip.c_str());
}

void format_endpoints(const struct ip6_hdr *ip6h, char *buf, size_t len)
{
    char src[INET6_ADDRSTRLEN];
    char dst[DESTINATION_TEXT_BUFSIZE];

    format_ipv6(&ip6h->ip6_src, src, sizeof(src));
    format_destination(&ip6h->ip6_dst, dst, sizeof(dst));

    snprintf(buf, len, "from=%s to=%s", src, dst);
}

void format_local_dns_log(const struct in6_addr *dns, const char *ifname, char *buf, size_t len)
{
    char ip[INET6_ADDRSTRLEN];

    format_ipv6(dns, ip, sizeof(ip));
    if (ifname != nullptr && ifname[0] != '\0')
        snprintf(buf, len, "%s(%s)", ip, ifname);
    else
        snprintf(buf, len, "%s", ip);
}

void addr_list_init(struct addr_list *list)
{
    list->buf[0] = '[';
    list->buf[1] = '\0';
    list->len = 1;
    list->first = true;
    list->truncated = false;
}

static void addr_list_append(struct addr_list *list, const struct in6_addr *addr)
{
    char ip[INET6_ADDRSTRLEN];
    char piece[INET6_ADDRSTRLEN + sizeof(",")];

    if (list->truncated)
        return;
    format_ipv6(addr, ip, sizeof(ip));
    const int n = snprintf(piece, sizeof(piece), "%s%s", list->first ? "" : ",", ip);
    if (
        n < 0 ||
        static_cast<size_t>(n) >= sizeof(piece) ||
        list->len + static_cast<size_t>(n) + sizeof(",...]") > sizeof(list->buf)
    ) {
        list->truncated = true;
        return;
    }

    memcpy(list->buf + list->len, piece, static_cast<size_t>(n));
    list->len += static_cast<size_t>(n);
    list->buf[list->len] = '\0';
    list->first = false;
}

void addr_list_append_wire_ipv6(struct addr_list *list, const uint8_t *data, size_t data_len)
{
    const uint8_t *end = data + data_len;

    for (const uint8_t *cursor = data; cursor < end && !list->truncated; cursor += sizeof(struct in6_addr)) {
        struct in6_addr addr;

        memcpy(&addr, cursor, sizeof(addr));
        addr_list_append(list, &addr);
    }
}

static const char *addr_list_finish(struct addr_list *list)
{
    const char *suffix = list->truncated ? ",...]" : "]";
    size_t suffix_len;

    if (list->first && list->truncated)
        suffix = "...]";

    suffix_len = strlen(suffix);
    if (list->len + suffix_len < sizeof(list->buf)) {
        memcpy(list->buf + list->len, suffix, suffix_len + 1);
        list->len += suffix_len;
    } else {
        list->buf[sizeof(list->buf) - sizeof("]")] = ']';
        list->buf[sizeof(list->buf) - 1] = '\0';
    }

    return list->buf;
}

static void format_hex(const uint8_t *data, size_t data_len, char *buf, size_t buf_len)
{
    static const char hex[] = "0123456789abcdef";
    static const char ellipsis[] = "...";
    const unsigned int nibble_bits = CHAR_BIT / 2U;
    const uint8_t low_nibble_mask = static_cast<uint8_t>((1U << nibble_bits) - 1U);
    size_t i;
    size_t out = 0;

    for (i = 0; i < data_len; i++) {
        const size_t required = sizeof("ff") +
            (i + 1U < data_len ? sizeof(ellipsis) - 1U : 0U);

        if (required > buf_len - out)
            break;
        buf[out++] = hex[data[i] >> nibble_bits];
        buf[out++] = hex[data[i] & low_nibble_mask];
    }

    if (i < data_len && sizeof(ellipsis) <= buf_len - out) {
        memcpy(buf + out, ellipsis, sizeof(ellipsis) - 1U);
        out += sizeof(ellipsis) - 1U;
    }
    buf[out] = '\0';
}

// DUID-LLT and DUID-LL both end in a link-layer address; type-specific
// fields sit between the DUID type and that address.
template <typename Duid>
static void format_duid_mac(const uint8_t *duid, size_t len, char *buf, size_t buf_len)
{
    const auto body_len = static_cast<uint32_t>(len - sizeof(uint16_t));
    const Duid value = Duid::from_bytes(duid + sizeof(uint16_t), body_len);

    if (value.hw_type == ARPHRD_ETHER)
        format_mac(value.lladdress.data(), buf, buf_len);
}

static void duid_ethernet_mac(const uint8_t *duid, size_t len, char *buf, size_t buf_len)
{
    const size_t duid_ll_len = sizeof(uint16_t) * 2U + ETH_ALEN;

    buf[0] = '\0';
    if (len < sizeof(uint16_t))
        return;

    const uint16_t duid_type = read_be16(duid);
    if (duid_type == Tins::DHCPv6::duid_llt::duid_id && len == duid_ll_len + sizeof(uint32_t))
        format_duid_mac<Tins::DHCPv6::duid_llt>(duid, len, buf, buf_len);
    else if (duid_type == Tins::DHCPv6::duid_ll::duid_id && len == duid_ll_len)
        format_duid_mac<Tins::DHCPv6::duid_ll>(duid, len, buf, buf_len);
}

void format_dhcpv6_client_log_fields(
    const uint8_t *duid,
    size_t len,
    char *client_id,
    size_t client_id_len,
    char *client_mac,
    size_t client_mac_len
)
{
    format_hex(duid, len, client_id, client_id_len);
    duid_ethernet_mac(duid, len, client_mac, client_mac_len);
}

static uint32_t read_transaction_id(const uint8_t *transaction_id)
{
    uint32_t value = 0;

    for (size_t i = 0; i < DHCPV6_TRANSACTION_ID_LEN; i++)
        value = (value << CHAR_BIT) | transaction_id[i];

    return value;
}

void format_ra_log_detail(
    char *detail,
    size_t detail_len,
    const char *endpoints,
    uint16_t original_lifetime,
    struct dns_option_stats *rdnss,
    unsigned int dnssl_removed,
    unsigned int pvd_removed
)
{
    snprintf(
        detail,
        detail_len,
        "type=RA %s router-lifetime=%u->%u rdnss=%s "
        "rdnss-options=%u rdnss-rewritten=%u rdnss-deduplicated=%u "
        "dnssl-removed=%u pvd-removed=%u",
        endpoints,
        original_lifetime,
        RA_NEUTRAL_ROUTER_LIFETIME,
        addr_list_finish(&rdnss->original),
        rdnss->options,
        rdnss->rewritten,
        rdnss->deduplicated,
        dnssl_removed,
        pvd_removed
    );
}

void format_dhcpv6_log_detail(
    char *detail,
    size_t detail_len,
    const char *message_name,
    const char *endpoints,
    const uint8_t *transaction_id,
    const char *client_id,
    const char *client_mac,
    struct dns_option_stats *dns,
    unsigned int domain_search_removed
)
{
    snprintf(
        detail,
        detail_len,
        "type=DHCPv6-%s %s xid=0x%0*x client-id=%s client-mac=%s "
        "dns=%s dns-options=%u dns-rewritten=%u dns-deduplicated=%u "
        "domain-search-removed=%u",
        message_name,
        endpoints,
        static_cast<int>(DHCPV6_TRANSACTION_ID_LEN * 2U),
        read_transaction_id(transaction_id),
        client_id[0] ? client_id : "-",
        client_mac[0] ? client_mac : "-",
        addr_list_finish(&dns->original),
        dns->options,
        dns->rewritten,
        dns->deduplicated,
        domain_search_removed
    );
}
