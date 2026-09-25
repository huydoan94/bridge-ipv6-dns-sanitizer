#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <net/if.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include <stdexcept>
#include <string>
#include <vector>

#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include <tins/dhcpv6.h>
#include <tins/icmpv6.h>
#include <tins/pdu.h>

#include "constants.h"
#include "logging.h"
#include "network.h"
#include "packet.h"
#include "packet-parser.h"

struct rdnss_option_wire {
    struct nd_opt_hdr header;
    uint16_t reserved;
    uint32_t lifetime;
} __attribute__((packed));

struct dhcpv6_direct_header_wire {
    uint8_t message_type;
    uint8_t transaction_id[DHCPV6_TRANSACTION_ID_LEN];
} __attribute__((packed));

struct dhcpv6_option_header_wire {
    uint16_t code;
    uint16_t length;
} __attribute__((packed));

struct app_ctx {
    bool verbose;
    std::vector<struct in6_addr> dns_servers;
};

enum sanitize_result {
    SANITIZE_ERROR = -1,
    SANITIZE_UNCHANGED = 0,
    SANITIZE_CHANGED,
    SANITIZE_DROP,
};

enum checksum_state {
    CHECKSUM_VALID = 0,
    CHECKSUM_INVALID,
    CHECKSUM_NOT_READY,
};

struct dhcpv6_option_view {
    uint16_t code;
    uint16_t data_len;
    size_t total_len;
    uint8_t *start;
    uint8_t *data;
};

static volatile sig_atomic_t running = 1;

static int dhcpv6_option_parse(uint8_t *cursor, uint8_t *end,
                               struct dhcpv6_option_view *option,
                               char *error, size_t error_len)
{
    const size_t header_len = sizeof(struct dhcpv6_option_header_wire);
    struct dhcpv6_option_header_wire *header;
    uint16_t data_len;
    uint8_t *data;

    if (cursor > end || (size_t)(end - cursor) < header_len) {
        set_error(error, error_len, "truncated DHCPv6 option header");
        return -1;
    }

    header = (struct dhcpv6_option_header_wire *)cursor;
    option->code = ntohs(header->code);
    data_len = ntohs(header->length);
    data = cursor + header_len;

    if ((size_t)data_len > (size_t)(end - data)) {
        set_error(error, error_len, "DHCPv6 option %u overruns packet",
                  option->code);
        return -1;
    }

    option->data_len = data_len;
    option->total_len = header_len + (size_t)data_len;
    option->start = cursor;
    option->data = data;
    return 0;
}

static void handle_signal(int sig)
{
    (void)sig;
    running = 0;
}

static int install_signal_handlers(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGINT, &sa, nullptr) < 0)
        return -1;
    if (sigaction(SIGTERM, &sa, nullptr) < 0)
        return -1;

    return 0;
}

static enum checksum_state
ra_checksum_state(const struct ip6_hdr *ip6h, const uint8_t *icmp,
                  size_t icmp_len, bool checksum_not_ready)
{
    if (checksum_not_ready)
        return CHECKSUM_NOT_READY;

    if (icmpv6_checksum(ip6h, icmp, icmp_len) == 0U)
        return CHECKSUM_VALID;

    return CHECKSUM_INVALID;
}

static enum checksum_state
udp_checksum_state(const struct ip6_hdr *ip6h, const struct udphdr *udp,
                   size_t udp_len, bool checksum_not_ready)
{
    if (checksum_not_ready)
        return CHECKSUM_NOT_READY;
    if (udp->check == 0)
        return CHECKSUM_INVALID;

    if (udp_ipv6_checksum(ip6h, (const uint8_t *)udp, udp_len) == 0U)
        return CHECKSUM_VALID;

    return CHECKSUM_INVALID;
}

static uint16_t preserve_checksum_state(uint16_t correct,
                                        enum checksum_state state,
                                        bool udp_checksum)
{
    uint16_t wire_value = correct;

    if (udp_checksum && wire_value == 0U)
        wire_value = UINT16_MAX;

    if (state == CHECKSUM_INVALID)
        wire_value ^= CHECKSUM_INVALID_XOR;

    return wire_value;
}

// The wire payload is identical for RDNSS and DHCPv6 DNS options.
static bool append_dns_addresses(
    std::vector<uint8_t>& output,
    const uint8_t *original,
    size_t original_len,
    const std::vector<struct in6_addr>& dns_servers
)
{
    const uint8_t *addresses = reinterpret_cast<const uint8_t *>(dns_servers.data());
    const size_t dns_bytes = dns_servers.size() * sizeof(struct in6_addr);
    const bool changed = original_len != dns_bytes ||
        memcmp(original, addresses, dns_bytes) != 0;

    output.insert(output.end(), addresses, addresses + dns_bytes);
    return changed;
}

static enum sanitize_result
sanitize_ra(struct ipv6_packet_view *packet,
            const struct ipv6_transport_view *transport,
            const std::vector<struct in6_addr>& dns_servers,
            bool checksum_not_ready,
            const char *endpoints, char *detail, size_t detail_len,
            char *error, size_t error_len)
{
    struct ip6_hdr *ip6h = packet->header;
    struct nd_router_advert *ra;
    std::vector<uint8_t> output;
    uint8_t *cursor;
    uint8_t *icmp_bytes = transport->header;
    uint8_t *options;
    uint8_t *options_end;
    size_t icmp_len = transport->len;
    size_t options_len;
    uint16_t original_lifetime;
    unsigned int rdnss_options = 0;
    unsigned int rdnss_addresses = 0;
    unsigned int rdnss_rewritten = 0;
    unsigned int rdnss_deduplicated;
    unsigned int dnssl_removed = 0;
    unsigned int pvd_removed = 0;
    bool kept_rdnss = false;
    bool send_signed = false;
    bool router_lifetime_changed;
    bool changed;
    bool log_details = detail != nullptr && detail_len != 0;
    enum checksum_state checksum_state;
    uint16_t new_checksum;
    struct addr_list original_rdnss;

    if (icmp_bytes == nullptr || icmp_len < sizeof(struct nd_router_advert)) {
        set_error(error, error_len, "truncated Router Advertisement");
        return SANITIZE_ERROR;
    }

    ra = (struct nd_router_advert *)icmp_bytes;
    checksum_state = ra_checksum_state(ip6h, icmp_bytes, icmp_len,
                                       checksum_not_ready);

    original_lifetime = ntohs(ra->nd_ra_router_lifetime);
    router_lifetime_changed = original_lifetime != RA_NEUTRAL_ROUTER_LIFETIME;
    if (router_lifetime_changed)
        ra->nd_ra_router_lifetime = htons(RA_NEUTRAL_ROUTER_LIFETIME);

    if (log_details)
        addr_list_init(&original_rdnss);

    options = icmp_bytes + sizeof(*ra);
    options_len = icmp_len - sizeof(*ra);
    options_end = options + options_len;
    cursor = options;

    while (cursor < options_end) {
        struct nd_opt_hdr *header;
        uint8_t *opt = cursor;
        size_t remaining = (size_t)(options_end - cursor);
        size_t opt_len;

        if (remaining < sizeof(*header)) {
            set_error(error, error_len, "truncated RA option header");
            return SANITIZE_ERROR;
        }

        header = (struct nd_opt_hdr *)opt;
        if (header->nd_opt_len == 0) {
            set_error(error, error_len, "zero-length RA option");
            return SANITIZE_ERROR;
        }

        opt_len = (size_t)header->nd_opt_len * NDP_OPTION_LEN_UNIT_OCTETS;
        if (opt_len > remaining) {
            set_error(error, error_len, "RA option overruns packet");
            return SANITIZE_ERROR;
        }

        cursor += opt_len;

        if (header->nd_opt_type == Tins::ICMPv6::RSA_SIGN)
            send_signed = true;

        if (header->nd_opt_type == ND_OPTION_PVD) {
            pvd_removed++;
            continue;
        }

        if (header->nd_opt_type == Tins::ICMPv6::DNS_SEARCH_LIST) {
            dnssl_removed++;
            continue;
        }

        if (header->nd_opt_type == Tins::ICMPv6::RECURSIVE_DNS_SERV) {
            const size_t fixed_len = sizeof(struct rdnss_option_wire);
            const size_t single_dns_len = fixed_len + sizeof(struct in6_addr);
            const size_t dns_bytes = dns_servers.size() * sizeof(struct in6_addr);
            const size_t configured_len = fixed_len + dns_bytes;
            size_t address_bytes;

            if (opt_len < single_dns_len || (opt_len - fixed_len) % sizeof(struct in6_addr) != 0) {
                set_error(error, error_len,
                          "invalid RDNSS option length %zu", opt_len);
                return SANITIZE_ERROR;
            }

            address_bytes = opt_len - fixed_len;
            rdnss_addresses += (unsigned int)(address_bytes / sizeof(struct in6_addr));

            if (log_details) {
                rdnss_options++;
                addr_list_append_wire_ipv6(&original_rdnss,
                                           opt + fixed_len,
                                           address_bytes);
            }

            if (kept_rdnss) {
                continue;
            }

            header->nd_opt_len = static_cast<uint8_t>(
                configured_len / NDP_OPTION_LEN_UNIT_OCTETS);
            output.insert(output.end(), opt, opt + fixed_len);
            rdnss_rewritten = append_dns_addresses(
                output, opt + fixed_len, address_bytes, dns_servers);
            kept_rdnss = true;
            continue;
        }

        output.insert(output.end(), opt, opt + opt_len);
    }

    rdnss_deduplicated =
        rdnss_addresses > dns_servers.size() ?
        rdnss_addresses - static_cast<unsigned int>(dns_servers.size()) : 0U;
    changed = router_lifetime_changed || rdnss_rewritten != 0 || rdnss_deduplicated != 0 || dnssl_removed != 0 || pvd_removed != 0;

    if (!changed)
        return SANITIZE_UNCHANGED;

    if (send_signed) {
        set_error(error, error_len,
                  "SEND-signed RA requires modification; DROP");
        return SANITIZE_DROP;
    }

    if (ipv6_packet_replace(packet, options, options_len, output) < 0) {
        set_error(error, error_len, "failed to replace RA options");
        return SANITIZE_ERROR;
    }

    icmp_len = sizeof(*ra) + output.size();
    ra->nd_ra_cksum = 0;
    new_checksum = icmpv6_checksum(ip6h, icmp_bytes, icmp_len);
    ra->nd_ra_cksum = htons(preserve_checksum_state(new_checksum,
                                                    checksum_state, false));

    if (log_details)
        format_ra_log_detail(detail, detail_len, endpoints, original_lifetime,
                             RA_NEUTRAL_ROUTER_LIFETIME, &original_rdnss,
                             rdnss_options, rdnss_rewritten,
                             rdnss_deduplicated, dnssl_removed, pvd_removed);

    return SANITIZE_CHANGED;
}

static enum sanitize_result
sanitize_dhcpv6(struct ipv6_packet_view *packet,
                const struct ipv6_transport_view *transport,
                const std::vector<struct in6_addr>& dns_servers,
                bool checksum_not_ready,
                const char *endpoints, char *detail, size_t detail_len,
                char *error, size_t error_len)
{
    struct ip6_hdr *ip6h = packet->header;
    struct udphdr *udp = (struct udphdr *)transport->header;
    std::vector<uint8_t> output;
    uint8_t *cursor;
    uint8_t *dhcp;
    struct dhcpv6_direct_header_wire *message;
    uint8_t *options_start;
    uint8_t *options_end;
    size_t available_udp_len = transport->len;
    size_t dhcp_len;
    size_t new_dhcp_len;
    uint16_t udp_len;
    Tins::DHCPv6::MessageType msg_type;
    const char *message_name;
    unsigned int dns_options = 0;
    unsigned int dns_addresses = 0;
    unsigned int dns_rewritten = 0;
    unsigned int dns_deduplicated;
    unsigned int domain_search_removed = 0;
    bool kept_dns = false;
    bool authenticated = false;
    bool changed;
    bool log_details = detail != nullptr && detail_len != 0;
    enum checksum_state checksum_state;
    uint16_t new_checksum;
    uint8_t transaction_id[DHCPV6_TRANSACTION_ID_LEN] = { 0 };
    char client_id[CLIENT_ID_BUFSIZE] = "";
    char client_mac[MAC_TEXT_BUFSIZE] = "";
    struct addr_list original_dns;

    if (udp == nullptr || available_udp_len < sizeof(*udp))
        return SANITIZE_UNCHANGED;

    udp_len = ntohs(udp->len);
    if (udp_len < sizeof(*udp))
        return SANITIZE_UNCHANGED;
    if ((size_t)udp_len > available_udp_len) {
        set_error(error, error_len,
                  "UDP length %u exceeds captured transport length %zu; DROP",
                  udp_len, available_udp_len);
        return SANITIZE_DROP;
    }

    checksum_state = udp_checksum_state(ip6h, udp, udp_len,
                                        checksum_not_ready);
    dhcp = (uint8_t *)udp + sizeof(*udp);
    dhcp_len = (size_t)udp_len - sizeof(*udp);

    if (dhcp_len < sizeof(struct dhcpv6_direct_header_wire))
        return SANITIZE_UNCHANGED;

    message = (struct dhcpv6_direct_header_wire *)dhcp;
    msg_type = static_cast<Tins::DHCPv6::MessageType>(message->message_type);
    if (msg_type != Tins::DHCPv6::ADVERTISE && msg_type != Tins::DHCPv6::REPLY)
        return SANITIZE_UNCHANGED;
    message_name = msg_type == Tins::DHCPv6::ADVERTISE ? "Advertise" : "Reply";

    if (log_details) {
        memcpy(transaction_id, message->transaction_id, sizeof(transaction_id));
        addr_list_init(&original_dns);
    }

    options_start = dhcp + sizeof(*message);
    options_end = dhcp + dhcp_len;
    cursor = options_start;

    while (cursor < options_end) {
        struct dhcpv6_option_view option;

        if (dhcpv6_option_parse(cursor, options_end,
                                &option, error, error_len) < 0)
            return SANITIZE_ERROR;

        cursor += option.total_len;

        if (option.code == Tins::DHCPv6::AUTH)
            authenticated = true;

        if (log_details && option.code == Tins::DHCPv6::CLIENTID && client_id[0] == '\0') {
            format_dhcpv6_client_log_fields(option.data, option.data_len,
                                            client_id, sizeof(client_id),
                                            client_mac, sizeof(client_mac));
        }

        if (option.code == Tins::DHCPv6::DOMAIN_LIST) {
            domain_search_removed++;
            continue;
        }

        if (option.code == Tins::DHCPv6::DNS_SERVERS) {
            struct dhcpv6_option_header_wire *header;
            uint8_t *opt;
            const size_t fixed_len = sizeof(struct dhcpv6_option_header_wire);
            const size_t dns_bytes = dns_servers.size() * sizeof(struct in6_addr);
            if (option.data_len == 0 || option.data_len % sizeof(struct in6_addr) != 0) {
                set_error(error, error_len,
                          "invalid DHCPv6 DNS option length %u",
                          option.data_len);
                return SANITIZE_ERROR;
            }

            dns_addresses += (unsigned int)(option.data_len / sizeof(struct in6_addr));

            if (log_details) {
                dns_options++;
                addr_list_append_wire_ipv6(&original_dns,
                                           option.data,
                                           option.data_len);
            }

            if (kept_dns) {
                continue;
            }

            opt = option.start;

            header = (struct dhcpv6_option_header_wire *)opt;
            header->length = htons(static_cast<uint16_t>(dns_bytes));
            output.insert(output.end(), opt, opt + fixed_len);
            dns_rewritten = append_dns_addresses(
                output, option.data, option.data_len, dns_servers);
            kept_dns = true;
            continue;
        }

        output.insert(output.end(), option.start, cursor);
    }

    dns_deduplicated =
        dns_addresses > dns_servers.size() ?
        dns_addresses - static_cast<unsigned int>(dns_servers.size()) : 0U;
    changed = dns_rewritten != 0 || dns_deduplicated != 0 || domain_search_removed != 0;

    if (!changed)
        return SANITIZE_UNCHANGED;

    if (authenticated) {
        set_error(error, error_len,
                  "authenticated DHCPv6 requires modification; DROP");
        return SANITIZE_DROP;
    }

    new_dhcp_len = sizeof(*message) + output.size();
    if (
        new_dhcp_len > UINT16_MAX - sizeof(*udp) ||
        ipv6_packet_replace(packet, options_start, static_cast<size_t>(options_end - options_start), output) < 0
    ) {
        set_error(error, error_len, "failed to replace DHCPv6 options");
        return SANITIZE_ERROR;
    }

    udp_len = static_cast<uint16_t>(sizeof(*udp) + new_dhcp_len);
    udp->len = htons(udp_len);
    udp->check = 0;
    new_checksum = udp_ipv6_checksum(ip6h, (const uint8_t *)udp, udp_len);
    udp->check = htons(preserve_checksum_state(new_checksum,
                                               checksum_state, true));

    if (log_details)
        format_dhcpv6_log_detail(detail, detail_len, message_name, endpoints,
                                 transaction_id, client_id, client_mac,
                                 &original_dns, dns_options, dns_rewritten,
                                 dns_deduplicated, domain_search_removed);

    return SANITIZE_CHANGED;
}

static int accept_unchanged(struct nfq_q_handle *qh, uint32_t id)
{
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
}

static int drop_packet(struct nfq_q_handle *qh, uint32_t id)
{
    return nfq_set_verdict(qh, id, NF_DROP, 0, nullptr);
}

static int verdict_with_modified_ipv6(struct nfq_q_handle *qh, uint32_t id,
                                      const struct ipv6_packet_view *packet)
{
    return nfq_set_verdict(qh, id, NF_ACCEPT,
                           (uint32_t)packet->captured_len, packet->data);
}

static int packet_cb(struct nfq_q_handle *qh,
                     struct nfgenmsg *nfmsg,
                     struct nfq_data *nfa,
                     void *data)
{
    struct app_ctx *ctx = static_cast<struct app_ctx *>(data);
    struct nfqnl_msg_packet_hdr *ph;
    unsigned char *payload = nullptr;
    struct ipv6_packet_view ipv6;
    struct ipv6_transport_view transport;
    struct in6_addr local_dns;
    std::vector<struct in6_addr> automatic_dns;
    const std::vector<struct in6_addr> *dns_servers;
    std::vector<uint8_t> packet_buffer;
    std::string dns_source_log;
    char dns_ifname[IF_NAMESIZE] = "";
    char local_dns_log[LOCAL_DNS_TEXT_BUFSIZE] = "";
    char endpoints[ENDPOINT_BUFSIZE];
    char detail[DETAIL_BUFSIZE] = "";
    char error[ERROR_BUFSIZE] = "";
    uint32_t id;
    uint32_t indev;
    uint32_t physindev;
    uint32_t skbinfo;
    int payload_len;
    int verdict;
    bool checksum_not_ready;
    enum ipv6_packet_result ipv6_result;
    enum ipv6_transport_result transport_result;
    enum sanitize_result result;

    ph = nfq_get_msg_packet_hdr(nfa);
    if (ph == nullptr) {
        log_error("NFQUEUE packet header unavailable");
        return -1;
    }
    id = ntohl(ph->packet_id);

    if (nfmsg == nullptr || nfmsg->nfgen_family != NFPROTO_BRIDGE) {
        if (ctx->verbose)
            log_info("id=%u unexpected NFQUEUE family; ACCEPT unchanged", id);
        return accept_unchanged(qh, id);
    }

    payload_len = nfq_get_payload(nfa, &payload);
    if (payload_len <= 0 || payload == nullptr) {
        log_error("id=%u: NFQUEUE payload unavailable; ACCEPT unchanged", id);
        return accept_unchanged(qh, id);
    }
    if (ctx->dns_servers.size() > 1U) {
        const size_t growth =
            (ctx->dns_servers.size() - 1U) * sizeof(struct in6_addr);
        packet_buffer.resize(static_cast<size_t>(payload_len) + growth);
        memcpy(packet_buffer.data(), payload, static_cast<size_t>(payload_len));
        payload = packet_buffer.data();
    }

    ipv6_result = parse_nfqueue_ipv6_payload(payload, (size_t)payload_len,
                                             &ipv6);
    if (ipv6_result == IPV6_PACKET_TRUNCATED) {
        log_error("id=%u: IPv6 declared length exceeds captured payload; DROP",
                  id);
        return drop_packet(qh, id);
    }
    if (ipv6_result != IPV6_PACKET_OK)
        return accept_unchanged(qh, id);
    if (!packet_buffer.empty())
        ipv6.capacity_end = packet_buffer.data() + packet_buffer.size();

    transport_result = parse_ipv6_transport(ipv6.data, ipv6.declared_len,
                                            &transport);
    if (transport_result != IPV6_TRANSPORT_FOUND)
        return accept_unchanged(qh, id);

    if (transport.fragmented) {
        log_error("id=%u: fragmented packet reached sanitizer queue; DROP", id);
        return drop_packet(qh, id);
    }

    if (transport.packet_type != Tins::PDU::ICMPv6 &&
        transport.packet_type != Tins::PDU::DHCPv6)
        return accept_unchanged(qh, id);

    if (ctx->verbose)
        format_endpoints(ipv6.header, endpoints, sizeof(endpoints));

    dns_servers = &ctx->dns_servers;
    if (dns_servers->empty()) {
        indev = nfq_get_indev(nfa);
        physindev = nfq_get_physindev(nfa);
        if (resolve_local_dns(indev, physindev, &local_dns,
                              ctx->verbose ? dns_ifname : nullptr,
                              ctx->verbose ? sizeof(dns_ifname) : 0U) < 0) {
            log_error("id=%u: no ULA found on ingress interface or bridge master; "
                      "ACCEPT unchanged", id);
            return accept_unchanged(qh, id);
        }
        automatic_dns.push_back(local_dns);
        dns_servers = &automatic_dns;

        if (ctx->verbose) {
            format_local_dns_log(&local_dns, dns_ifname,
                                 local_dns_log, sizeof(local_dns_log));
            dns_source_log = local_dns_log;
        }
    } else if (ctx->verbose) {
        dns_source_log = "configured(" +
            std::to_string(dns_servers->size()) + ")";
    }

    skbinfo = nfq_get_skbinfo(nfa);
    checksum_not_ready = (skbinfo & NFQA_SKB_CSUMNOTREADY) != 0U;

    const auto sanitize = transport.packet_type == Tins::PDU::ICMPv6 ?
        sanitize_ra : sanitize_dhcpv6;
    result = sanitize(&ipv6, &transport, *dns_servers,
                      checksum_not_ready,
                      ctx->verbose ? endpoints : nullptr,
                      ctx->verbose ? detail : nullptr,
                      ctx->verbose ? sizeof(detail) : 0U,
                      error, sizeof(error));

    if (result == SANITIZE_ERROR) {
        log_error("id=%u: %s; ACCEPT unchanged",
                  id, error[0] ? error : "packet sanitizer failed");
        return accept_unchanged(qh, id);
    }

    if (result == SANITIZE_DROP) {
        log_error("id=%u: %s", id, error[0] ? error : "packet policy DROP");
        return drop_packet(qh, id);
    }

    if (result == SANITIZE_UNCHANGED)
        return accept_unchanged(qh, id);

    if (ctx->verbose)
        log_info("id=%u dns-source=%s %s",
                 id, dns_source_log.c_str(), detail);

    verdict = verdict_with_modified_ipv6(qh, id, &ipv6);
    if (verdict < 0) {
        log_error("id=%u: could not send modified IPv6 verdict; "
                  "ACCEPT unchanged", id);
        return accept_unchanged(qh, id);
    }

    return verdict;
}

static bool parse_queue_number(const char *text, uint16_t *queue_number)
{
    if (text == nullptr || queue_number == nullptr)
        return false;

    try {
        const std::string input(text);
        size_t parsed_length = 0;
        const int value = std::stoi(input, &parsed_length, 10);

        if (parsed_length != input.length() || value < 0 || value > UINT16_MAX)
            return false;

        *queue_number = static_cast<uint16_t>(value);
        return true;
    } catch (const std::invalid_argument &) {
        return false;
    } catch (const std::out_of_range &) {
        return false;
    }
}

static bool parse_dns_server(const char *text, struct in6_addr *dns_server)
{
    return text != nullptr &&
        dns_server != nullptr &&
        inet_pton(AF_INET6, text, dns_server) == 1;
}

static void usage(const char *prog)
{
    fprintf(stdout, "Usage: %s -q QUEUE_NUMBER [-d DNS_SERVER]... [-v]\n", prog);
}

int main(int argc, char **argv)
{
    struct app_ctx ctx = {};
    struct nfq_handle *h = nullptr;
    struct nfq_q_handle *qh = nullptr;
    struct pollfd pfd;
    int fd;
    int rv;
    uint16_t queue_number = 0;
    int opt;
    int exit_status = EXIT_SUCCESS;
    ssize_t recv_len;
    bool queue_number_set = false;
    char buf[NFQ_RECV_BUFSIZE] __attribute__((aligned));

    while ((opt = getopt(argc, argv, "d:q:vh")) != -1) {
        switch (opt) {
        case 'd': {
            struct in6_addr dns_server;

            if (ctx.dns_servers.size() >= MAX_CONFIGURED_DNS_SERVERS) {
                log_error("too many DNS servers; maximum is %zu",
                          MAX_CONFIGURED_DNS_SERVERS);
                return EXIT_FAILURE;
            }
            if (!parse_dns_server(optarg, &dns_server)) {
                log_error("invalid IPv6 DNS server '%s'", optarg);
                return EXIT_FAILURE;
            }
            ctx.dns_servers.push_back(dns_server);
            break;
        }
        case 'q':
            if (!parse_queue_number(optarg, &queue_number)) {
                log_error("invalid queue number '%s'; expected 0-65535", optarg);
                usage(argv[0]);
                return EXIT_FAILURE;
            }
            queue_number_set = true;
            break;
        case 'v':
            ctx.verbose = true;
            break;
        case 'h':
            usage(argv[0]);
            return EXIT_SUCCESS;
        default:
            usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    if (optind != argc) {
        log_error("unexpected positional argument '%s'", argv[optind]);
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    if (!queue_number_set) {
        log_error("queue number is required");
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    /* procd captures these streams; keep every message immediately visible. */
    setvbuf(stdout, nullptr, _IOLBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);

    log_info("starting version %s", PROGRAM_VERSION);
    if (!ctx.dns_servers.empty())
        log_info("using %zu configured DNS server(s)", ctx.dns_servers.size());

    if (install_signal_handlers() < 0) {
        log_error("failed to install signal handlers: %s", strerror(errno));
        exit_status = EXIT_FAILURE;
        goto out;
    }

    h = nfq_open();
    if (h == nullptr) {
        log_error("nfq_open() failed");
        exit_status = EXIT_FAILURE;
        goto out;
    }

    qh = nfq_create_queue(h, queue_number, &packet_cb, &ctx);
    if (qh == nullptr) {
        log_error("nfq_create_queue(%u) failed", queue_number);
        exit_status = EXIT_FAILURE;
        goto out_nfq;
    }

    /*
     * nft's `queue ... bypass` only handles the no-listener case. A full
     * kernel NFQUEUE is dropped by default, so explicitly enable the kernel
     * fail-open flag as well.
     */
    if (nfq_set_queue_flags(qh, NFQA_CFG_F_FAIL_OPEN,
                            NFQA_CFG_F_FAIL_OPEN) < 0) {
        log_error("nfq_set_queue_flags(FAIL_OPEN) failed: %s",
                  strerror(errno));
        exit_status = EXIT_FAILURE;
        goto out_queue;
    }

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, COPY_RANGE) < 0) {
        log_error("nfq_set_mode() failed");
        exit_status = EXIT_FAILURE;
        goto out_queue;
    }

    if (nfq_set_queue_maxlen(qh, QUEUE_MAXLEN) < 0)
        log_error("nfq_set_queue_maxlen(%u) failed", QUEUE_MAXLEN);

    fd = nfq_fd(h);
    pfd.fd = fd;
    pfd.events = POLLIN;
    pfd.revents = 0;

    log_info("listening on NFQUEUE %u", queue_number);

    while (running) {
        rv = poll(&pfd, 1, POLL_TIMEOUT_MS);
        if (rv == 0)
            continue;
        if (rv < 0) {
            if (errno == EINTR)
                continue;
            log_error("poll() failed: %s", strerror(errno));
            exit_status = EXIT_FAILURE;
            break;
        }

        if (!(pfd.revents & POLLIN)) {
            if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
                log_error("NFQUEUE socket poll error: revents=0x%x",
                          pfd.revents);
                exit_status = EXIT_FAILURE;
                break;
            }
            continue;
        }

        recv_len = recv(fd, buf, sizeof(buf), 0);
        if (recv_len >= 0) {
            if (nfq_handle_packet(h, buf, (int)recv_len) < 0) {
                log_error("nfq_handle_packet() failed");
                exit_status = EXIT_FAILURE;
                break;
            }
            continue;
        }

        if (errno == EINTR)
            continue;
        if (errno == ENOBUFS) {
            log_error("NFQUEUE receive buffer overflow");
            continue;
        }

        log_error("recv() failed: %s", strerror(errno));
        exit_status = EXIT_FAILURE;
        break;
    }

    log_info("stopping");

out_queue:
    if (qh != nullptr)
        nfq_destroy_queue(qh);
out_nfq:
    if (h != nullptr)
        nfq_close(h);
out:
    log_info("exiting");
    return exit_status;
}
