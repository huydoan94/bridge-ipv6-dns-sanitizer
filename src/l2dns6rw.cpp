#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
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

#include <algorithm>
#include <new>
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
    std::string configured_dns_log;
    local_dns_cache dns_cache;
    std::vector<uint8_t> packet_buffer;
    std::vector<uint8_t> option_buffer;
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

// One packet's sanitizer input and output; detail and error hold DETAIL_BUFSIZE
// and ERROR_BUFSIZE bytes, and a null endpoints string disables the log detail.
struct sanitize_job {
    struct ipv6_packet_view *packet;
    const struct ipv6_transport_view *transport;
    const std::vector<struct in6_addr> *dns_servers;
    std::vector<uint8_t> *output;
    const char *endpoints;
    char *detail;
    char *error;
    bool checksum_not_ready;
};

static volatile sig_atomic_t running = 1;

static int dhcpv6_option_parse(
    uint8_t *cursor,
    uint8_t *end,
    struct dhcpv6_option_view *option,
    char *error,
    size_t error_len
)
{
    const size_t header_len = sizeof(struct dhcpv6_option_header_wire);

    if (cursor > end || static_cast<size_t>(end - cursor) < header_len) {
        set_error(error, error_len, "truncated DHCPv6 option header");
        return -1;
    }

    const auto *header = reinterpret_cast<const struct dhcpv6_option_header_wire *>(cursor);
    uint8_t *data = cursor + header_len;
    option->code = ntohs(header->code);
    option->data_len = ntohs(header->length);
    if (option->data_len > static_cast<size_t>(end - data)) {
        set_error(error, error_len, "DHCPv6 option %u overruns packet", option->code);
        return -1;
    }

    option->total_len = header_len + option->data_len;
    option->start = cursor;
    option->data = data;
    return 0;
}

static void handle_signal(int)
{
    running = 0;
}

static int install_signal_handlers(void)
{
    struct sigaction sa = {};

    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGINT, &sa, nullptr) < 0 || sigaction(SIGTERM, &sa, nullptr) < 0)
        return -1;
    return 0;
}

static enum checksum_state ra_checksum_state(
    const struct ip6_hdr *ip6h,
    const uint8_t *icmp,
    size_t icmp_len,
    bool checksum_not_ready
)
{
    if (checksum_not_ready)
        return CHECKSUM_NOT_READY;
    if (icmpv6_checksum(ip6h, icmp, icmp_len) == 0U)
        return CHECKSUM_VALID;
    return CHECKSUM_INVALID;
}

static enum checksum_state udp_checksum_state(
    const struct ip6_hdr *ip6h,
    const struct udphdr *udp,
    size_t udp_len,
    bool checksum_not_ready
)
{
    if (checksum_not_ready)
        return CHECKSUM_NOT_READY;
    if (udp->check == 0)
        return CHECKSUM_INVALID;
    if (udp_ipv6_checksum(ip6h, reinterpret_cast<const uint8_t *>(udp), udp_len) == 0U)
        return CHECKSUM_VALID;
    return CHECKSUM_INVALID;
}

// A packet that arrived with a bad checksum leaves with a bad checksum.
static uint16_t preserve_checksum_state(uint16_t correct, enum checksum_state state)
{
    return state == CHECKSUM_INVALID ? correct ^ CHECKSUM_INVALID_XOR : correct;
}

// Counts one RDNSS or DHCPv6 DNS option and returns true for the first one,
// which carries the configured list; later options are dropped as duplicates.
static bool dns_option_count(
    struct dns_option_stats *stats,
    const uint8_t *addresses,
    size_t address_bytes,
    bool log_details
)
{
    stats->addresses += static_cast<unsigned int>(address_bytes / sizeof(struct in6_addr));
    if (log_details)
        addr_list_append_wire_ipv6(&stats->original, addresses, address_bytes);
    return ++stats->options == 1U;
}

// The wire payload is identical for RDNSS and DHCPv6 DNS options.
static bool append_dns_addresses(
    std::vector<uint8_t> &output,
    const uint8_t *original,
    size_t original_len,
    const std::vector<struct in6_addr> &dns_servers
)
{
    const uint8_t *addresses = reinterpret_cast<const uint8_t *>(dns_servers.data());
    const size_t dns_bytes = dns_servers.size() * sizeof(struct in6_addr);

    output.insert(output.end(), addresses, addresses + dns_bytes);
    return original_len != dns_bytes || memcmp(original, addresses, dns_bytes) != 0;
}

static unsigned int excess_addresses(unsigned int addresses, size_t configured)
{
    return addresses > configured ? addresses - static_cast<unsigned int>(configured) : 0U;
}

static enum sanitize_result sanitize_ra(const struct sanitize_job *job)
{
    const std::vector<struct in6_addr> &dns_servers = *job->dns_servers;
    std::vector<uint8_t> &output = *job->output;
    struct ipv6_packet_view *packet = job->packet;
    uint8_t *icmp = job->transport->header;
    const size_t icmp_len = job->transport->len;
    const bool log_details = job->endpoints != nullptr;
    const size_t rdnss_fixed_len = sizeof(struct rdnss_option_wire);
    struct dns_option_stats rdnss = {};
    unsigned int dnssl_removed = 0;
    unsigned int pvd_removed = 0;
    bool send_signed = false;

    if (icmp_len < sizeof(struct nd_router_advert)) {
        set_error(job->error, ERROR_BUFSIZE, "truncated Router Advertisement");
        return SANITIZE_ERROR;
    }

    auto *ra = reinterpret_cast<struct nd_router_advert *>(icmp);
    const uint16_t original_lifetime = ntohs(ra->nd_ra_router_lifetime);
    uint8_t *options = icmp + sizeof(*ra);
    const size_t options_len = icmp_len - sizeof(*ra);
    uint8_t *options_end = options + options_len;

    if (log_details)
        addr_list_init(&rdnss.original);
    output.clear();
    output.reserve(options_len + dns_servers.size() * sizeof(struct in6_addr));

    for (uint8_t *cursor = options; cursor < options_end;) {
        const size_t remaining = static_cast<size_t>(options_end - cursor);
        const auto *header = reinterpret_cast<const struct nd_opt_hdr *>(cursor);

        if (remaining < sizeof(*header)) {
            set_error(job->error, ERROR_BUFSIZE, "truncated RA option header");
            return SANITIZE_ERROR;
        }
        if (header->nd_opt_len == 0) {
            set_error(job->error, ERROR_BUFSIZE, "zero-length RA option");
            return SANITIZE_ERROR;
        }

        const size_t opt_len = header->nd_opt_len * NDP_OPTION_LEN_UNIT_OCTETS;
        if (opt_len > remaining) {
            set_error(job->error, ERROR_BUFSIZE, "RA option overruns packet");
            return SANITIZE_ERROR;
        }

        uint8_t *opt = cursor;
        cursor += opt_len;

        switch (header->nd_opt_type) {
        case ND_OPTION_PVD:
            pvd_removed++;
            continue;
        case Tins::ICMPv6::DNS_SEARCH_LIST:
            dnssl_removed++;
            continue;
        case Tins::ICMPv6::RECURSIVE_DNS_SERV: {
            const size_t address_bytes = opt_len - rdnss_fixed_len;

            if (address_bytes == 0 || address_bytes % sizeof(struct in6_addr) != 0) {
                set_error(job->error, ERROR_BUFSIZE, "invalid RDNSS option length %zu", opt_len);
                return SANITIZE_ERROR;
            }
            if (dns_option_count(&rdnss, opt + rdnss_fixed_len, address_bytes, log_details)) {
                const size_t length_offset = output.size() + offsetof(struct nd_opt_hdr, nd_opt_len);
                const size_t rdnss_len = rdnss_fixed_len + dns_servers.size() * sizeof(struct in6_addr);

                output.insert(output.end(), opt, opt + rdnss_fixed_len);
                output[length_offset] = static_cast<uint8_t>(rdnss_len / NDP_OPTION_LEN_UNIT_OCTETS);
                rdnss.rewritten = append_dns_addresses(
                    output,
                    opt + rdnss_fixed_len,
                    address_bytes,
                    dns_servers
                );
            }
            continue;
        }
        case Tins::ICMPv6::RSA_SIGN:
            send_signed = true;
            break;
        }
        output.insert(output.end(), opt, cursor);
    }

    rdnss.deduplicated = excess_addresses(rdnss.addresses, dns_servers.size());
    if (
        original_lifetime == RA_NEUTRAL_ROUTER_LIFETIME &&
        rdnss.rewritten == 0 &&
        rdnss.deduplicated == 0 &&
        dnssl_removed == 0 &&
        pvd_removed == 0
    ) {
        return SANITIZE_UNCHANGED;
    }

    if (send_signed) {
        set_error(job->error, ERROR_BUFSIZE, "SEND-signed RA requires modification; DROP");
        return SANITIZE_DROP;
    }

    const enum checksum_state checksum_state = ra_checksum_state(
        packet->header,
        icmp,
        icmp_len,
        job->checksum_not_ready
    );
    if (ipv6_packet_replace(packet, options, options_len, output) < 0) {
        set_error(job->error, ERROR_BUFSIZE, "failed to replace RA options");
        return SANITIZE_ERROR;
    }

    ra->nd_ra_router_lifetime = htons(RA_NEUTRAL_ROUTER_LIFETIME);
    ra->nd_ra_cksum = 0;
    const uint16_t checksum = icmpv6_checksum(packet->header, icmp, sizeof(*ra) + output.size());
    ra->nd_ra_cksum = htons(preserve_checksum_state(checksum, checksum_state));

    if (log_details) {
        format_ra_log_detail(
            job->detail,
            DETAIL_BUFSIZE,
            job->endpoints,
            original_lifetime,
            &rdnss,
            dnssl_removed,
            pvd_removed
        );
    }
    return SANITIZE_CHANGED;
}

static enum sanitize_result sanitize_dhcpv6(const struct sanitize_job *job)
{
    const std::vector<struct in6_addr> &dns_servers = *job->dns_servers;
    std::vector<uint8_t> &output = *job->output;
    struct ipv6_packet_view *packet = job->packet;
    auto *udp = reinterpret_cast<struct udphdr *>(job->transport->header);
    const size_t available_udp_len = job->transport->len;
    const bool log_details = job->endpoints != nullptr;
    struct dns_option_stats dns = {};
    unsigned int domain_search_removed = 0;
    bool authenticated = false;
    char client_id[CLIENT_ID_BUFSIZE] = "";
    char client_mac[MAC_TEXT_BUFSIZE] = "";

    if (available_udp_len < sizeof(*udp))
        return SANITIZE_UNCHANGED;

    const size_t udp_len = ntohs(udp->len);
    if (udp_len < sizeof(*udp))
        return SANITIZE_UNCHANGED;
    if (udp_len > available_udp_len) {
        set_error(
            job->error,
            ERROR_BUFSIZE,
            "UDP length %zu exceeds captured transport length %zu; DROP",
            udp_len,
            available_udp_len
        );
        return SANITIZE_DROP;
    }

    uint8_t *dhcp = reinterpret_cast<uint8_t *>(udp) + sizeof(*udp);
    const size_t dhcp_len = udp_len - sizeof(*udp);
    if (dhcp_len < sizeof(struct dhcpv6_direct_header_wire))
        return SANITIZE_UNCHANGED;

    const auto *message = reinterpret_cast<const struct dhcpv6_direct_header_wire *>(dhcp);
    const auto msg_type = static_cast<Tins::DHCPv6::MessageType>(message->message_type);
    if (msg_type != Tins::DHCPv6::ADVERTISE && msg_type != Tins::DHCPv6::REPLY)
        return SANITIZE_UNCHANGED;

    uint8_t *options = dhcp + sizeof(*message);
    const size_t options_len = dhcp_len - sizeof(*message);
    uint8_t *options_end = options + options_len;

    if (log_details)
        addr_list_init(&dns.original);
    output.clear();
    output.reserve(options_len + dns_servers.size() * sizeof(struct in6_addr));

    for (uint8_t *cursor = options; cursor < options_end;) {
        struct dhcpv6_option_view option;

        if (dhcpv6_option_parse(cursor, options_end, &option, job->error, ERROR_BUFSIZE) < 0)
            return SANITIZE_ERROR;
        cursor += option.total_len;

        switch (option.code) {
        case Tins::DHCPv6::AUTH:
            authenticated = true;
            break;
        case Tins::DHCPv6::CLIENTID:
            if (log_details && client_id[0] == '\0') {
                format_dhcpv6_client_log_fields(
                    option.data,
                    option.data_len,
                    client_id,
                    sizeof(client_id),
                    client_mac,
                    sizeof(client_mac)
                );
            }
            break;
        case Tins::DHCPv6::DOMAIN_LIST:
            domain_search_removed++;
            continue;
        case Tins::DHCPv6::DNS_SERVERS:
            if (option.data_len == 0 || option.data_len % sizeof(struct in6_addr) != 0) {
                set_error(job->error, ERROR_BUFSIZE, "invalid DHCPv6 DNS option length %u", option.data_len);
                return SANITIZE_ERROR;
            }
            if (dns_option_count(&dns, option.data, option.data_len, log_details)) {
                const struct dhcpv6_option_header_wire header = {
                    htons(option.code),
                    htons(static_cast<uint16_t>(dns_servers.size() * sizeof(struct in6_addr))),
                };
                const auto *header_bytes = reinterpret_cast<const uint8_t *>(&header);

                output.insert(output.end(), header_bytes, header_bytes + sizeof(header));
                dns.rewritten = append_dns_addresses(output, option.data, option.data_len, dns_servers);
            }
            continue;
        }
        output.insert(output.end(), option.start, cursor);
    }

    dns.deduplicated = excess_addresses(dns.addresses, dns_servers.size());
    if (dns.rewritten == 0 && dns.deduplicated == 0 && domain_search_removed == 0)
        return SANITIZE_UNCHANGED;

    if (authenticated) {
        set_error(job->error, ERROR_BUFSIZE, "authenticated DHCPv6 requires modification; DROP");
        return SANITIZE_DROP;
    }

    const enum checksum_state checksum_state = udp_checksum_state(
        packet->header,
        udp,
        udp_len,
        job->checksum_not_ready
    );
    if (ipv6_packet_replace(packet, options, options_len, output) < 0) {
        set_error(job->error, ERROR_BUFSIZE, "failed to replace DHCPv6 options");
        return SANITIZE_ERROR;
    }

    // Successful IPv6 replacement already guarantees this fits in 16 bits.
    const auto new_udp_len = static_cast<uint16_t>(sizeof(*udp) + sizeof(*message) + output.size());
    udp->len = htons(new_udp_len);
    udp->check = 0;
    const auto *udp_bytes = reinterpret_cast<const uint8_t *>(udp);
    uint16_t checksum = udp_ipv6_checksum(packet->header, udp_bytes, new_udp_len);
    // RFC 8200 section 8.1: a computed UDP checksum of zero is sent as 0xffff.
    if (checksum == 0U)
        checksum = UINT16_MAX;
    udp->check = htons(preserve_checksum_state(checksum, checksum_state));

    if (log_details) {
        format_dhcpv6_log_detail(
            job->detail,
            DETAIL_BUFSIZE,
            msg_type == Tins::DHCPv6::ADVERTISE ? "Advertise" : "Reply",
            job->endpoints,
            message->transaction_id,
            client_id,
            client_mac,
            &dns,
            domain_search_removed
        );
    }
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

static int verdict_with_modified_ipv6(
    struct nfq_q_handle *qh,
    uint32_t id,
    const struct ipv6_packet_view *packet,
    std::vector<uint8_t> &payload
)
{
    if (packet->captured_len > NFQ_MAX_PAYLOAD) {
        errno = EMSGSIZE;
        return -1;
    }

    // Reuse the growth buffer directly; otherwise copy only modified packets.
    const bool already_owned = payload.data() == packet->data;
    payload.resize(NLA_ALIGN(packet->captured_len));
    if (!already_owned)
        memcpy(payload.data(), packet->data, packet->captured_len);
    std::fill(payload.begin() + static_cast<std::ptrdiff_t>(packet->captured_len), payload.end(), 0);
    return nfq_set_verdict(qh, id, NF_ACCEPT, static_cast<uint32_t>(packet->captured_len), payload.data());
}

static int packet_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
try {
    struct app_ctx *ctx = static_cast<struct app_ctx *>(data);
    const struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    unsigned char *payload = nullptr;
    struct ipv6_packet_view ipv6;
    struct ipv6_transport_view transport;

    if (ph == nullptr) {
        log_error("NFQUEUE packet header unavailable");
        return -1;
    }
    const uint32_t id = ntohl(ph->packet_id);

    if (nfmsg == nullptr || nfmsg->nfgen_family != NFPROTO_BRIDGE) {
        if (ctx->verbose)
            log_info("id=%u unexpected NFQUEUE family; ACCEPT unchanged", id);
        return accept_unchanged(qh, id);
    }

    const int payload_len = nfq_get_payload(nfa, &payload);
    if (payload_len <= 0 || payload == nullptr) {
        log_error("id=%u: NFQUEUE payload unavailable; ACCEPT unchanged", id);
        return accept_unchanged(qh, id);
    }

    switch (parse_nfqueue_ipv6_payload(payload, static_cast<size_t>(payload_len), &ipv6)) {
    case IPV6_PACKET_OK:
        break;
    case IPV6_PACKET_TRUNCATED:
        log_error("id=%u: IPv6 declared length exceeds captured payload; DROP", id);
        return drop_packet(qh, id);
    case IPV6_PACKET_PASSTHROUGH:
        return accept_unchanged(qh, id);
    }

    if (parse_ipv6_transport(ipv6.data, ipv6.declared_len, &transport) != IPV6_TRANSPORT_FOUND)
        return accept_unchanged(qh, id);
    if (transport.fragmented) {
        log_error("id=%u: fragmented packet reached sanitizer queue; DROP", id);
        return drop_packet(qh, id);
    }
    if (transport.packet_type != Tins::PDU::ICMPv6 && transport.packet_type != Tins::PDU::DHCPv6)
        return accept_unchanged(qh, id);

    const std::vector<struct in6_addr> *dns_servers = &ctx->dns_servers;
    const char *dns_source_log = ctx->configured_dns_log.c_str();
    if (dns_servers->empty()) {
        local_dns_cache *dns_cache = &ctx->dns_cache;

        dns_cache->refresh();
        const local_dns_source *source = dns_cache->find(nfq_get_indev(nfa), nfq_get_physindev(nfa));
        if (source == nullptr) {
            if (ctx->verbose)
                log_info("id=%u: no cached ingress ULA; ACCEPT unchanged", id);
            return accept_unchanged(qh, id);
        }
        dns_servers = &source->servers;
        dns_source_log = source->description.c_str();
    }

    // Rewriting one DNS address into several can grow the packet in place.
    if (dns_servers->size() > 1U) {
        const size_t transport_offset = static_cast<size_t>(transport.header - ipv6.data);

        ipv6_packet_move(&ipv6, ctx->packet_buffer, (dns_servers->size() - 1U) * sizeof(struct in6_addr));
        transport.header = ipv6.data + transport_offset;
    }

    char endpoints[ENDPOINT_BUFSIZE];
    char detail[DETAIL_BUFSIZE] = "";
    char error[ERROR_BUFSIZE] = "";
    struct sanitize_job job;

    if (ctx->verbose)
        format_endpoints(ipv6.header, endpoints, sizeof(endpoints));
    job.packet = &ipv6;
    job.transport = &transport;
    job.dns_servers = dns_servers;
    job.output = &ctx->option_buffer;
    job.endpoints = ctx->verbose ? endpoints : nullptr;
    job.detail = detail;
    job.error = error;
    job.checksum_not_ready = (nfq_get_skbinfo(nfa) & NFQA_SKB_CSUMNOTREADY) != 0U;

    switch (transport.packet_type == Tins::PDU::ICMPv6 ? sanitize_ra(&job) : sanitize_dhcpv6(&job)) {
    case SANITIZE_ERROR:
        log_error("id=%u: %s; ACCEPT unchanged", id, error[0] ? error : "packet sanitizer failed");
        return accept_unchanged(qh, id);
    case SANITIZE_DROP:
        log_error("id=%u: %s", id, error[0] ? error : "packet policy DROP");
        return drop_packet(qh, id);
    case SANITIZE_UNCHANGED:
        return accept_unchanged(qh, id);
    case SANITIZE_CHANGED:
        break;
    }

    if (ctx->verbose)
        log_info("id=%u dns-source=%s %s", id, dns_source_log, detail);

    const int verdict = verdict_with_modified_ipv6(qh, id, &ipv6, ctx->packet_buffer);
    if (verdict >= 0)
        return verdict;
    log_error("id=%u: could not send modified IPv6 verdict (%s); ACCEPT unchanged", id, strerror(errno));
    return accept_unchanged(qh, id);
} catch (const std::bad_alloc &) {
    const struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);

    if (ph == nullptr) {
        log_error("out of memory; NFQUEUE packet header unavailable");
        return -1;
    }
    const uint32_t id = ntohl(ph->packet_id);
    log_error("id=%u: out of memory while processing packet; ACCEPT unchanged", id);
    return accept_unchanged(qh, id);
}

static bool parse_queue_number(const char *text, uint16_t *queue_number)
{
    try {
        const std::string input(text);
        size_t parsed_length = 0;
        const int value = std::stoi(input, &parsed_length);

        if (parsed_length != input.length() || value < 0 || value > UINT16_MAX)
            return false;
        *queue_number = static_cast<uint16_t>(value);
        return true;
    } catch (const std::logic_error &) {
        // std::invalid_argument or std::out_of_range from std::stoi.
        return false;
    }
}

static void usage(const char *prog)
{
    fprintf(stdout, "Usage: %s -q QUEUE_NUMBER [-d DNS_SERVER]... [-v]\n", prog);
}

// Blocks until a packet arrives, then hands it to packet_cb; returns the exit status.
static int receive_packets(struct nfq_handle *h)
{
    struct pollfd pfd = {};
    char buf[NFQ_RECV_BUFSIZE] __attribute__((aligned));

    pfd.fd = nfq_fd(h);
    pfd.events = POLLIN;
    while (running) {
        // No timeout: only a packet or SIGINT/SIGTERM (EINTR) wakes the daemon.
        if (poll(&pfd, 1, -1) < 0) {
            if (errno == EINTR)
                continue;
            log_error("poll() failed: %s", strerror(errno));
            return EXIT_FAILURE;
        }
        if (!(pfd.revents & POLLIN)) {
            log_error("NFQUEUE socket poll error: revents=0x%x", pfd.revents);
            return EXIT_FAILURE;
        }

        const ssize_t recv_len = recv(pfd.fd, buf, sizeof(buf), 0);
        if (recv_len < 0) {
            if (errno == EINTR)
                continue;
            if (errno == ENOBUFS) {
                log_error("NFQUEUE receive buffer overflow");
                continue;
            }
            log_error("recv() failed: %s", strerror(errno));
            return EXIT_FAILURE;
        }
        if (nfq_handle_packet(h, buf, static_cast<int>(recv_len)) < 0) {
            log_error("nfq_handle_packet() failed");
            return EXIT_FAILURE;
        }
    }
    return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
    struct app_ctx ctx = {};
    struct nfq_handle *h = nullptr;
    struct nfq_q_handle *qh = nullptr;
    uint16_t queue_number = 0;
    bool queue_number_set = false;
    int exit_status = EXIT_FAILURE;
    int opt;

    while ((opt = getopt(argc, argv, "d:q:vh")) != -1) {
        switch (opt) {
        case 'd': {
            struct in6_addr dns_server;

            if (ctx.dns_servers.size() >= MAX_CONFIGURED_DNS_SERVERS) {
                log_error("too many DNS servers; maximum is %zu", MAX_CONFIGURED_DNS_SERVERS);
                return EXIT_FAILURE;
            }
            if (inet_pton(AF_INET6, optarg, &dns_server) != 1) {
                log_error("invalid IPv6 DNS server '%s'", optarg);
                return EXIT_FAILURE;
            }
            ctx.dns_servers.push_back(dns_server);
            break;
        }
        case 'q':
            if (!parse_queue_number(optarg, &queue_number)) {
                log_error(
                    "invalid queue number '%s'; expected 0-%u",
                    optarg,
                    static_cast<unsigned int>(UINT16_MAX)
                );
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

    ctx.configured_dns_log = "configured(" + std::to_string(ctx.dns_servers.size()) + ")";
    log_info("starting version %s", PROGRAM_VERSION);
    if (!ctx.dns_servers.empty())
        log_info("using %zu configured DNS server(s)", ctx.dns_servers.size());

    if (install_signal_handlers() < 0) {
        log_error("failed to install signal handlers: %s", strerror(errno));
        goto out;
    }

    h = nfq_open();
    if (h == nullptr) {
        log_error("nfq_open() failed");
        goto out;
    }

    qh = nfq_create_queue(h, queue_number, &packet_cb, &ctx);
    if (qh == nullptr) {
        log_error("nfq_create_queue(%u) failed", queue_number);
        goto out_nfq;
    }

    /*
     * nft's `queue ... bypass` only handles the no-listener case. A full
     * kernel NFQUEUE is dropped by default, so explicitly enable the kernel
     * fail-open flag as well.
     */
    if (nfq_set_queue_flags(qh, NFQA_CFG_F_FAIL_OPEN, NFQA_CFG_F_FAIL_OPEN) < 0) {
        log_error("nfq_set_queue_flags(FAIL_OPEN) failed: %s", strerror(errno));
        goto out_queue;
    }
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, COPY_RANGE) < 0) {
        log_error("nfq_set_mode() failed");
        goto out_queue;
    }
    if (nfq_set_queue_maxlen(qh, QUEUE_MAXLEN) < 0)
        log_error("nfq_set_queue_maxlen(%u) failed", QUEUE_MAXLEN);

    if (ctx.dns_servers.empty())
        ctx.dns_cache.refresh();
    log_info("listening on NFQUEUE %u", queue_number);
    exit_status = receive_packets(h);
    log_info("stopping");

out_queue:
    nfq_destroy_queue(qh);
out_nfq:
    nfq_close(h);
out:
    log_info("exiting");
    return exit_status;
}
