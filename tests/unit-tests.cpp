#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <netpacket/packet.h>
#include <sys/stat.h>

#include <algorithm>
#include <chrono>
#include <functional>
#include <limits>
#include <random>
#include <new>
#include <cstdlib>
#include <string>
#include <vector>

// Fail one allocation, then allow the recovery path and verdict recorder to run.
static int allocations_before_failure = -1;
static bool allocation_failed = false;
static size_t allocation_count = 0;

void *operator new(size_t size)
{
    ++allocation_count;
    if (allocations_before_failure == 0) {
        allocations_before_failure = -1;
        allocation_failed = true;
        throw std::bad_alloc();
    }
    if (allocations_before_failure > 0)
        --allocations_before_failure;
    if (void *memory = std::malloc(size == 0 ? 1 : size))
        return memory;
    throw std::bad_alloc();
}

void operator delete(void *memory) noexcept
{
    std::free(memory);
}

#include "../src/network.h"
#include "../src/packet.h"

static int test_getifaddrs(ifaddrs **addresses);
static void test_freeifaddrs(ifaddrs *addresses);
static int test_mkstemp(char *path);
static size_t test_fwrite(const void *data, size_t size, size_t count, FILE *file);
static ssize_t test_readlink(const char *path, char *buf, size_t bufsiz);
static int test_poll(struct pollfd *fds, nfds_t nfds, int timeout);
static ssize_t test_recv(int sockfd, void *buf, size_t len, int flags);

#define readlink test_readlink
#define getifaddrs test_getifaddrs
#define freeifaddrs test_freeifaddrs
#define mkstemp test_mkstemp
#define fwrite test_fwrite
#include "../src/network.cpp"
#undef fwrite
#undef mkstemp
#undef freeifaddrs
#undef getifaddrs
#undef readlink
#include "../src/packet.cpp"

#include "../src/logging.cpp"
#include "../src/packet-parser.cpp"

#define main bridge_ipv6_dns_sanitizer_daemon_main
#define poll test_poll
#define recv test_recv
#include "../src/bridge-ipv6-dns-sanitizer.cpp"
#undef recv
#undef poll
#undef main

namespace {

struct test_state {
    unsigned int assertions;
    unsigned int failures;
    unsigned int tests;
    const char *current_test;
};

test_state state = {};

void expect(bool condition, const char *expression, const char *file, int line)
{
    state.assertions++;
    if (condition)
        return;

    state.failures++;
    std::fprintf(stderr, "FAIL %s: %s (%s:%d)\n",
                 state.current_test, expression, file, line);
}

#define EXPECT(expression) expect((expression), #expression, __FILE__, __LINE__)

void run_test(const char *name, const std::function<void()>& test)
{
    const unsigned int failures_before = state.failures;

    state.current_test = name;
    state.tests++;
    test();
    if (state.failures == failures_before)
        std::printf("PASS %s\n", name);
}

in6_addr address(const char *text)
{
    in6_addr result = {};

    EXPECT(inet_pton(AF_INET6, text, &result) == 1);
    return result;
}

void append_bytes(std::vector<uint8_t>& output, const void *data, size_t len)
{
    const uint8_t *first = static_cast<const uint8_t *>(data);

    output.insert(output.end(), first, first + len);
}

void append_be16(std::vector<uint8_t>& output, uint16_t value)
{
    value = htons(value);
    append_bytes(output, &value, sizeof(value));
}

std::vector<uint8_t> ra_option(uint8_t type, uint8_t units,
                               uint8_t fill = 0)
{
    std::vector<uint8_t> option(static_cast<size_t>(units) * NDP_OPTION_LEN_UNIT_OCTETS,
                                fill);

    if (option.size() >= sizeof(struct nd_opt_hdr)) {
        option[0] = type;
        option[1] = units;
    }
    return option;
}

std::vector<uint8_t> rdnss_option(const std::vector<in6_addr>& addresses)
{
    const size_t fixed_len = sizeof(struct rdnss_option_wire);
    const size_t option_len = fixed_len + addresses.size() * sizeof(in6_addr);
    std::vector<uint8_t> option(option_len);
    struct rdnss_option_wire *rdnss = reinterpret_cast<struct rdnss_option_wire *>(option.data());

    rdnss->header.nd_opt_type = Tins::ICMPv6::RECURSIVE_DNS_SERV;
    rdnss->header.nd_opt_len = static_cast<uint8_t>(option_len / NDP_OPTION_LEN_UNIT_OCTETS);
    rdnss->lifetime = htonl(600U);
    for (size_t i = 0; i < addresses.size(); ++i)
        std::memcpy(option.data() + fixed_len + i * sizeof(in6_addr),
                    &addresses[i], sizeof(in6_addr));
    return option;
}

std::vector<uint8_t> dhcp_option(uint16_t code,
                                 const std::vector<uint8_t>& data)
{
    std::vector<uint8_t> option;

    append_be16(option, code);
    append_be16(option, static_cast<uint16_t>(data.size()));
    option.insert(option.end(), data.begin(), data.end());
    return option;
}

std::vector<uint8_t> wire_addresses(const std::vector<in6_addr>& addresses)
{
    std::vector<uint8_t> bytes;

    for (const in6_addr& item : addresses)
        append_bytes(bytes, &item, sizeof(item));
    return bytes;
}

struct packet_fixture {
    std::vector<uint8_t> bytes;
    ipv6_packet_view packet;
    ipv6_transport_view transport;

    packet_fixture(uint8_t next_header, const std::vector<uint8_t>& payload,
                   size_t captured_tail = 0)
        : bytes(sizeof(struct ip6_hdr) + payload.size() + captured_tail),
          packet(), transport()
    {
        struct ip6_hdr *ip6h = reinterpret_cast<struct ip6_hdr *>(bytes.data());

        ip6h->ip6_flow = htonl(6U << 28U);
        ip6h->ip6_plen = htons(static_cast<uint16_t>(payload.size()));
        ip6h->ip6_nxt = next_header;
        ip6h->ip6_hlim = 64;
        ip6h->ip6_src = address("fd00::1");
        ip6h->ip6_dst = address("ff02::1");
        if (!payload.empty())
            std::memcpy(bytes.data() + sizeof(*ip6h), payload.data(), payload.size());
        for (size_t i = 0; i < captured_tail; ++i)
            bytes[sizeof(*ip6h) + payload.size() + i] = static_cast<uint8_t>(0xa0U + i);
        refresh(payload.size());
    }

    void refresh(size_t declared_payload_len)
    {
        packet.data = bytes.data();
        packet.header = reinterpret_cast<struct ip6_hdr *>(bytes.data());
        packet.declared_len = sizeof(struct ip6_hdr) + declared_payload_len;
        packet.captured_len = bytes.size();
        packet.declared_end = bytes.data() + packet.declared_len;
        packet.captured_end = bytes.data() + packet.captured_len;
        packet.capacity_end = packet.captured_end;
        transport.packet_type = Tins::PDU::UNKNOWN;
        transport.header = bytes.data() + sizeof(struct ip6_hdr);
        transport.len = declared_payload_len;
        transport.fragmented = false;
    }
};

packet_fixture router_advertisement(uint16_t lifetime,
                                    const std::vector<std::vector<uint8_t> >& options,
                                    bool valid_checksum = true,
                                    size_t captured_tail = 0)
{
    std::vector<uint8_t> payload(sizeof(struct nd_router_advert));
    struct nd_router_advert *ra;

    for (const std::vector<uint8_t>& option : options)
        payload.insert(payload.end(), option.begin(), option.end());
    ra = reinterpret_cast<struct nd_router_advert *>(payload.data());
    ra->nd_ra_type = ND_ROUTER_ADVERT;
    ra->nd_ra_router_lifetime = htons(lifetime);

    packet_fixture fixture(IPPROTO_ICMPV6, payload, captured_tail);
    ra = reinterpret_cast<struct nd_router_advert *>(fixture.transport.header);
    ra->nd_ra_cksum = 0;
    uint16_t checksum = icmpv6_checksum(fixture.packet.header,
                                        fixture.transport.header,
                                        fixture.transport.len);
    if (!valid_checksum)
        checksum ^= 1U;
    ra->nd_ra_cksum = htons(checksum);
    return fixture;
}

packet_fixture dhcpv6_packet(uint8_t message_type,
                             const std::vector<std::vector<uint8_t> >& options,
                             bool valid_checksum = true,
                             size_t captured_tail = 0)
{
    std::vector<uint8_t> dhcp(sizeof(struct dhcpv6_direct_header_wire));
    struct dhcpv6_direct_header_wire *message = reinterpret_cast<struct dhcpv6_direct_header_wire *>(dhcp.data());

    message->message_type = message_type;
    message->transaction_id[0] = 0x12;
    message->transaction_id[1] = 0x34;
    message->transaction_id[2] = 0x56;
    for (const std::vector<uint8_t>& option : options)
        dhcp.insert(dhcp.end(), option.begin(), option.end());

    std::vector<uint8_t> payload(sizeof(struct udphdr) + dhcp.size());
    struct udphdr *udp = reinterpret_cast<struct udphdr *>(payload.data());

    udp->source = htons(547U);
    udp->dest = htons(546U);
    udp->len = htons(static_cast<uint16_t>(payload.size()));
    std::memcpy(payload.data() + sizeof(*udp), dhcp.data(), dhcp.size());

    packet_fixture fixture(IPPROTO_UDP, payload, captured_tail);
    udp = reinterpret_cast<struct udphdr *>(fixture.transport.header);
    udp->check = 0;
    uint16_t checksum = udp_ipv6_checksum(fixture.packet.header,
                                          fixture.transport.header,
                                          fixture.transport.len);
    if (checksum == 0U)
        checksum = UINT16_MAX;
    if (!valid_checksum)
        checksum ^= 1U;
    udp->check = htons(checksum);
    return fixture;
}

void expect_text_contains(const char *text, const char *needle)
{
    EXPECT(std::strstr(text, needle) != nullptr);
}

struct verdict_call {
    uint32_t id;
    uint32_t verdict;
    uint32_t data_len;
    std::vector<uint8_t> data;
};

struct nfq_stub_state {
    bool header_available;
    struct nfqnl_msg_packet_hdr header;
    unsigned char *payload;
    int payload_len;
    uint32_t indev;
    uint32_t physindev;
    uint32_t skbinfo;
    int modified_verdict_result;
    int plain_verdict_result;
    std::vector<verdict_call> verdicts;
    bool open_succeeds;
    bool create_queue_succeeds;
    uint16_t queue_number;
    std::string configured_dns_log;
    int queue_flags_result;
    int mode_result;
    int maxlen_result;
    int handle_packet_result;
    int destroy_calls;
    int close_calls;
};

nfq_stub_state nfq_stub;
int resolver_result;
ifaddrs network_rows[4];
sockaddr_ll network_links[2];
sockaddr_in6 network_address;
unsigned int discovery_calls;
unsigned int discovery_frees;
bool cache_file_failure;
bool cache_write_failure;
unsigned int cache_writes;

enum readlink_mode {
    READLINK_FAIL,
    READLINK_TEXT,
};

readlink_mode current_readlink_mode;
std::string readlink_text;

struct poll_step {
    int result;
    short revents;
    int error;
    bool stop;
};

struct recv_step {
    ssize_t result;
    int error;
};

std::vector<poll_step> poll_steps;
std::vector<recv_step> recv_steps;
size_t poll_index;
size_t recv_index;
int sigaction_calls;
int sigaction_fail_call;

void reset_stubs()
{
    std::memset(&nfq_stub.header, 0, sizeof(nfq_stub.header));
    nfq_stub.header_available = true;
    nfq_stub.header.packet_id = htonl(42U);
    nfq_stub.payload = nullptr;
    nfq_stub.payload_len = -1;
    nfq_stub.indev = 11U;
    nfq_stub.physindev = 12U;
    nfq_stub.skbinfo = 0;
    nfq_stub.modified_verdict_result = 0;
    nfq_stub.plain_verdict_result = 0;
    nfq_stub.verdicts.clear();
    nfq_stub.open_succeeds = true;
    nfq_stub.create_queue_succeeds = true;
    nfq_stub.queue_number = 0;
    nfq_stub.configured_dns_log.clear();
    nfq_stub.queue_flags_result = 0;
    nfq_stub.mode_result = 0;
    nfq_stub.maxlen_result = 0;
    nfq_stub.handle_packet_result = 0;
    nfq_stub.destroy_calls = 0;
    nfq_stub.close_calls = 0;
    resolver_result = 0;
    std::memset(network_rows, 0, sizeof(network_rows));
    std::memset(network_links, 0, sizeof(network_links));
    network_address = {};
    network_links[0].sll_family = AF_PACKET;
    network_links[0].sll_ifindex = 11;
    network_links[1].sll_family = AF_PACKET;
    network_links[1].sll_ifindex = 12;
    network_address.sin6_family = AF_INET6;
    network_address.sin6_addr = address("fd00::53");
    network_rows[0].ifa_name = const_cast<char *>("br-lan");
    network_rows[0].ifa_addr = reinterpret_cast<sockaddr *>(&network_links[0]);
    network_rows[0].ifa_next = &network_rows[1];
    network_rows[1].ifa_name = const_cast<char *>("br-lan");
    network_rows[1].ifa_addr = reinterpret_cast<sockaddr *>(&network_address);
    network_rows[1].ifa_next = &network_rows[2];
    network_rows[2].ifa_name = const_cast<char *>("vxlan0");
    network_rows[2].ifa_addr = reinterpret_cast<sockaddr *>(&network_links[1]);
    discovery_calls = 0;
    discovery_frees = 0;
    cache_file_failure = false;
    cache_write_failure = false;
    cache_writes = 0;
    current_readlink_mode = READLINK_FAIL;
    readlink_text.clear();
    poll_steps.clear();
    recv_steps.clear();
    poll_index = 0;
    recv_index = 0;
    sigaction_calls = 0;
    sigaction_fail_call = 0;
}

void prepare_callback_payload(std::vector<uint8_t>& bytes)
{
    nfq_stub.payload = bytes.data();
    nfq_stub.payload_len = static_cast<int>(bytes.size());
}

nfgenmsg bridge_message()
{
    nfgenmsg message = {};

    message.nfgen_family = NFPROTO_BRIDGE;
    return message;
}

void expect_last_verdict(uint32_t verdict, uint32_t data_len)
{
    EXPECT(!nfq_stub.verdicts.empty());
    if (nfq_stub.verdicts.empty())
        return;
    EXPECT(nfq_stub.verdicts.back().verdict == verdict);
    EXPECT(nfq_stub.verdicts.back().data_len == data_len);
}

} // namespace

static int test_getifaddrs(ifaddrs **addresses)
{
    ++discovery_calls;
    if (resolver_result < 0) {
        errno = EIO;
        return -1;
    }
    *addresses = network_rows;
    return 0;
}

static void test_freeifaddrs(ifaddrs *addresses)
{
    (void)addresses;
    ++discovery_frees;
}

static size_t test_fwrite(const void *data, size_t size, size_t count, FILE *file)
{
    ++cache_writes;
    if (cache_write_failure) {
        errno = ENOSPC;
        return 0;
    }
    return fwrite(data, size, count, file);
}

static int test_mkstemp(char *path)
{
    if (cache_file_failure) {
        errno = EACCES;
        return -1;
    }
    return mkstemp(path);
}

static ssize_t test_readlink(const char *path, char *buf, size_t bufsiz)
{
    (void)path;
    if (current_readlink_mode == READLINK_FAIL) {
        errno = ENOENT;
        return -1;
    }
    const size_t count = std::min(bufsiz, readlink_text.size());
    std::memcpy(buf, readlink_text.data(), count);
    return static_cast<ssize_t>(count);
}

extern "C" int sigaction(int signum, const struct sigaction *act,
                         struct sigaction *oldact) noexcept
{
    (void)signum;
    (void)act;
    (void)oldact;
    sigaction_calls++;
    if (sigaction_fail_call == sigaction_calls) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

static int test_poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    (void)timeout;
    if (poll_index >= poll_steps.size()) {
        running = 0;
        return 0;
    }
    const poll_step step = poll_steps[poll_index++];
    if (nfds != 0)
        fds[0].revents = step.revents;
    if (step.stop)
        running = 0;
    errno = step.error;
    return step.result;
}

static ssize_t test_recv(int sockfd, void *buf, size_t len, int flags)
{
    (void)sockfd;
    (void)flags;
    if (recv_index >= recv_steps.size()) {
        errno = EIO;
        return -1;
    }
    const recv_step step = recv_steps[recv_index++];
    if (step.result > 0 && static_cast<size_t>(step.result) <= len)
        std::memset(buf, 0x5a, static_cast<size_t>(step.result));
    errno = step.error;
    return step.result;
}

extern "C" {

struct nfq_handle *nfq_open(void)
{
    return nfq_stub.open_succeeds ? reinterpret_cast<struct nfq_handle *>(1) : nullptr;
}

int nfq_close(struct nfq_handle *handle)
{
    (void)handle;
    nfq_stub.close_calls++;
    return 0;
}

struct nfq_q_handle *nfq_create_queue(struct nfq_handle *handle, uint16_t num,
                                      nfq_callback *callback, void *data)
{
    (void)handle;
    nfq_stub.queue_number = num;
    (void)callback;
    nfq_stub.configured_dns_log = static_cast<app_ctx *>(data)->configured_dns_log;
    return nfq_stub.create_queue_succeeds ? reinterpret_cast<struct nfq_q_handle *>(1) : nullptr;
}

int nfq_destroy_queue(struct nfq_q_handle *handle)
{
    (void)handle;
    nfq_stub.destroy_calls++;
    return 0;
}

int nfq_handle_packet(struct nfq_handle *handle, char *buf, int len)
{
    (void)handle;
    (void)buf;
    (void)len;
    return nfq_stub.handle_packet_result;
}

int nfq_fd(struct nfq_handle *handle)
{
    (void)handle;
    return 7;
}

int nfq_set_mode(struct nfq_q_handle *handle, uint8_t mode, unsigned int range)
{
    (void)handle;
    (void)mode;
    (void)range;
    return nfq_stub.mode_result;
}

int nfq_set_queue_maxlen(struct nfq_q_handle *handle, uint32_t length)
{
    (void)handle;
    (void)length;
    return nfq_stub.maxlen_result;
}

int nfq_set_queue_flags(struct nfq_q_handle *handle, uint32_t mask, uint32_t flags)
{
    (void)handle;
    (void)mask;
    (void)flags;
    return nfq_stub.queue_flags_result;
}

int nfq_set_verdict(struct nfq_q_handle *handle, uint32_t id, uint32_t verdict,
                    uint32_t data_len, const unsigned char *data)
{
    (void)handle;
    // The real verdict library does not allocate through C++ operator new.
    allocations_before_failure = -1;
    EXPECT(data_len <= 65531U);
    for (size_t index = data_len; index < NLA_ALIGN(data_len); ++index)
        EXPECT(data[index] == 0U);
    verdict_call call = { id, verdict, data_len, std::vector<uint8_t>() };
    if (data != nullptr && data_len != 0)
        call.data.assign(data, data + data_len);
    nfq_stub.verdicts.push_back(call);
    return data_len == 0 ? nfq_stub.plain_verdict_result : nfq_stub.modified_verdict_result;
}

struct nfqnl_msg_packet_hdr *nfq_get_msg_packet_hdr(struct nfq_data *data)
{
    (void)data;
    return nfq_stub.header_available ? &nfq_stub.header : nullptr;
}

uint32_t nfq_get_indev(struct nfq_data *data)
{
    (void)data;
    return nfq_stub.indev;
}

uint32_t nfq_get_physindev(struct nfq_data *data)
{
    (void)data;
    return nfq_stub.physindev;
}

uint32_t nfq_get_skbinfo(struct nfq_data *data)
{
    (void)data;
    return nfq_stub.skbinfo;
}

int nfq_get_payload(struct nfq_data *data, unsigned char **payload)
{
    (void)data;
    *payload = nfq_stub.payload;
    return nfq_stub.payload_len;
}

} // extern "C"

namespace {

void test_packet_basics()
{
    const uint8_t bytes[] = { 0xaa, 0x12, 0x34, 0xbb };
    EXPECT(read_be16(bytes + 1) == 0x1234U);

    std::string master;
    current_readlink_mode = READLINK_FAIL;
    EXPECT(!get_bridge_master("eth0", master));
    current_readlink_mode = READLINK_TEXT;
    readlink_text = "/sys/class/net/br-lan";
    EXPECT(get_bridge_master("eth0", master));
    EXPECT(master == "br-lan");
    readlink_text = "br-test";
    EXPECT(get_bridge_master("eth0", master));
    EXPECT(master == "br-test");
    readlink_text.clear();
    EXPECT(!get_bridge_master("eth0", master));


}

void test_ipv6_packet_parsing()
{
    ipv6_packet_view view = {};
    std::vector<uint8_t> short_packet(sizeof(struct ip6_hdr) - 1U);
    EXPECT(parse_nfqueue_ipv6_payload(nullptr, 0, &view) == IPV6_PACKET_PASSTHROUGH);
    EXPECT(parse_nfqueue_ipv6_payload(short_packet.data(), short_packet.size(), nullptr) == IPV6_PACKET_PASSTHROUGH);
    EXPECT(parse_nfqueue_ipv6_payload(short_packet.data(), short_packet.size(), &view) == IPV6_PACKET_PASSTHROUGH);

    packet_fixture fixture(IPPROTO_NONE, std::vector<uint8_t>(8U), 4U);
    fixture.bytes[0] = 0x40;
    EXPECT(parse_nfqueue_ipv6_payload(fixture.bytes.data(), fixture.bytes.size(), &view) == IPV6_PACKET_PASSTHROUGH);
    fixture.bytes[0] = 0x60;
    fixture.packet.header->ip6_plen = 0;
    EXPECT(parse_nfqueue_ipv6_payload(fixture.bytes.data(), fixture.bytes.size(), &view) == IPV6_PACKET_PASSTHROUGH);
    fixture.packet.header->ip6_plen = htons(100U);
    EXPECT(parse_nfqueue_ipv6_payload(fixture.bytes.data(), fixture.bytes.size(), &view) == IPV6_PACKET_TRUNCATED);
    fixture.packet.header->ip6_plen = htons(8U);
    EXPECT(parse_nfqueue_ipv6_payload(fixture.bytes.data(), fixture.bytes.size(), &view) == IPV6_PACKET_OK);
    EXPECT(view.declared_len == sizeof(struct ip6_hdr) + 8U);
    EXPECT(view.captured_len == fixture.bytes.size());
    EXPECT(view.declared_end == fixture.bytes.data() + sizeof(struct ip6_hdr) + 8U);
    EXPECT(view.captured_end == fixture.bytes.data() + fixture.bytes.size());
}

void test_ipv6_packet_replacement()
{
    packet_fixture fixture(IPPROTO_NONE, { 1, 2, 3, 4, 5, 6 }, 2U);
    const size_t captured_len = fixture.packet.captured_len;
    fixture.bytes.resize(captured_len + 16U);
    fixture.refresh(6U);
    fixture.packet.captured_len = captured_len;
    fixture.packet.captured_end = fixture.bytes.data() + captured_len;
    uint8_t *payload = fixture.bytes.data() + sizeof(struct ip6_hdr);

    EXPECT(ipv6_packet_replace(&fixture.packet, payload + 5, 2, {}) == -1);
    EXPECT(ipv6_packet_replace(&fixture.packet, payload, 1, std::vector<uint8_t>(32U)) == -1);
    EXPECT(ipv6_packet_replace(&fixture.packet, payload + 1, 2, { 7, 8, 9, 10 }) == 0);
    EXPECT(fixture.packet.captured_len == captured_len + 2U);
    EXPECT(ntohs(fixture.packet.header->ip6_plen) == 8U);
    EXPECT(std::vector<uint8_t>(payload, fixture.packet.captured_end) ==
           std::vector<uint8_t>({ 1, 7, 8, 9, 10, 4, 5, 6, 0xa0, 0xa1 }));

    EXPECT(ipv6_packet_replace(&fixture.packet, payload + 1, 4, { 2 }) == 0);
    EXPECT(ntohs(fixture.packet.header->ip6_plen) == 5U);
    EXPECT(std::vector<uint8_t>(payload, fixture.packet.captured_end) ==
           std::vector<uint8_t>({ 1, 2, 4, 5, 6, 0xa0, 0xa1 }));
}

void test_logging_formatters()
{
    char buffer[DETAIL_BUFSIZE];
    char tiny[5];
    struct ip6_hdr ip6h = {};

    set_error(buffer, sizeof(buffer), "error %d", 7);
    EXPECT(std::strcmp(buffer, "error 7") == 0);
    set_error(tiny, sizeof(tiny), "abcdef");
    EXPECT(std::strcmp(tiny, "abcd") == 0);
    tiny[0] = 'x';
    set_error(tiny, 0, "ignored");
    EXPECT(tiny[0] == 'x');

    ip6h.ip6_src = address("fd00::1");
    ip6h.ip6_dst = address("ff02::1");
    format_endpoints(&ip6h, buffer, sizeof(buffer));
    EXPECT(std::strcmp(buffer, "from=fd00::1 to=ff02::1(all-nodes)") == 0);
    ip6h.ip6_dst = address("ff02::1:2");
    format_endpoints(&ip6h, buffer, sizeof(buffer));
    EXPECT(std::strcmp(buffer, "from=fd00::1 to=ff02::1:2(all-dhcp-agents)") == 0);
    ip6h.ip6_dst = address("2001:db8::1");
    format_endpoints(&ip6h, buffer, sizeof(buffer));
    EXPECT(std::strcmp(buffer, "from=fd00::1 to=2001:db8::1") == 0);

    in6_addr dns = address("fd00::53");
    format_local_dns_log(&dns, "br-lan", buffer, sizeof(buffer));
    EXPECT(std::strcmp(buffer, "fd00::53(br-lan)") == 0);
    format_local_dns_log(&dns, "", buffer, sizeof(buffer));
    EXPECT(std::strcmp(buffer, "fd00::53") == 0);
    format_local_dns_log(&dns, nullptr, buffer, sizeof(buffer));
    EXPECT(std::strcmp(buffer, "fd00::53") == 0);
}

void test_address_lists_and_details()
{
    addr_list list;
    char detail[DETAIL_BUFSIZE];
    const in6_addr first = address("fd00::1");
    const in6_addr second = address("fd00::2");
    std::vector<uint8_t> addresses = wire_addresses({ first, second });

    addr_list_init(&list);
    addr_list_append_wire_ipv6(&list, addresses.data(), 0);
    format_ra_log_detail(detail, sizeof(detail), "from=a to=b", 10, 0,
                         &list, 0, 0, 0, 0, 0);
    expect_text_contains(detail, "rdnss=[]");

    addr_list_init(&list);
    addr_list_append_wire_ipv6(&list, addresses.data(), addresses.size());
    format_ra_log_detail(detail, sizeof(detail), "from=a to=b", 10, 0,
                         &list, 1, 1, 1, 2, 3);
    expect_text_contains(detail, "rdnss=[fd00::1,fd00::2]");
    expect_text_contains(detail, "rdnss-options=1");
    expect_text_contains(detail, "dnssl-removed=2 pvd-removed=3");

    addr_list_init(&list);
    std::vector<in6_addr> many;
    for (unsigned int i = 0; i < 80U; ++i) {
        in6_addr item = address("fd00::1");
        item.s6_addr[14] = static_cast<uint8_t>(i >> 8U);
        item.s6_addr[15] = static_cast<uint8_t>(i);
        many.push_back(item);
    }
    addresses = wire_addresses(many);
    addr_list_append_wire_ipv6(&list, addresses.data(), addresses.size());
    EXPECT(list.truncated);
    format_ra_log_detail(detail, sizeof(detail), "x", 0, 0,
                         &list, 1, 0, 0, 0, 0);
    expect_text_contains(detail, ",...]");

    addr_list_init(&list);
    const uint8_t xid[] = { 0x12, 0x34, 0x56 };
    format_dhcpv6_log_detail(detail, sizeof(detail), "Reply", "from=a to=b",
                             xid, "", "", &list, 0, 0, 0, 0);
    expect_text_contains(detail, "type=DHCPv6-Reply");
    expect_text_contains(detail, "xid=0x123456");
    expect_text_contains(detail, "client-id=- client-mac=-");

    addr_list forced_truncated = {};
    std::strcpy(forced_truncated.buf, "[");
    forced_truncated.len = 1U;
    forced_truncated.first = true;
    forced_truncated.truncated = true;
    EXPECT(std::strcmp(addr_list_finish(&forced_truncated), "[...]") == 0);

    addr_list forced_full = {};
    std::memset(forced_full.buf, 'x', sizeof(forced_full.buf));
    forced_full.len = sizeof(forced_full.buf) - 1U;
    forced_full.first = false;
    forced_full.truncated = false;
    EXPECT(addr_list_finish(&forced_full)[sizeof(forced_full.buf) - 2U] == ']');
}

void test_duid_formatting()
{
    char client_id[CLIENT_ID_BUFSIZE];
    char client_mac[MAC_TEXT_BUFSIZE];
    const std::vector<uint8_t> llt = {
        0x00, 0x01, 0x00, 0x01, 0x11, 0x22, 0x33, 0x44,
        0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
    };
    const std::vector<uint8_t> ll = {
        0x00, 0x03, 0x00, 0x01, 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
    };

    format_dhcpv6_client_log_fields(llt.data(), llt.size(),
                                    client_id, sizeof(client_id),
                                    client_mac, sizeof(client_mac));
    EXPECT(std::strcmp(client_id, "000100011122334402aabbccddee") == 0);
    EXPECT(std::strcmp(client_mac, "02:aa:bb:cc:dd:ee") == 0);
    format_dhcpv6_client_log_fields(ll.data(), ll.size(),
                                    client_id, sizeof(client_id),
                                    client_mac, sizeof(client_mac));
    EXPECT(std::strcmp(client_mac, "02:aa:bb:cc:dd:ee") == 0);

    std::vector<uint8_t> non_ethernet = ll;
    non_ethernet[3] = 6;
    format_dhcpv6_client_log_fields(non_ethernet.data(), non_ethernet.size(),
                                    client_id, sizeof(client_id),
                                    client_mac, sizeof(client_mac));
    EXPECT(client_mac[0] == '\0');
    std::vector<uint8_t> non_ethernet_llt = llt;
    non_ethernet_llt[3] = 6;
    format_dhcpv6_client_log_fields(non_ethernet_llt.data(), non_ethernet_llt.size(),
                                    client_id, sizeof(client_id),
                                    client_mac, sizeof(client_mac));
    EXPECT(client_mac[0] == '\0');
    std::vector<uint8_t> extra = ll;
    extra.push_back(0xff);
    format_dhcpv6_client_log_fields(extra.data(), extra.size(),
                                    client_id, sizeof(client_id),
                                    client_mac, sizeof(client_mac));
    EXPECT(client_mac[0] == '\0');
    const uint8_t short_duid[] = { 1 };
    format_dhcpv6_client_log_fields(short_duid, sizeof(short_duid),
                                    client_id, sizeof(client_id),
                                    client_mac, sizeof(client_mac));
    EXPECT(client_mac[0] == '\0');

    char small_id[6];
    format_dhcpv6_client_log_fields(llt.data(), llt.size(),
                                    small_id, sizeof(small_id), nullptr, 0);
    EXPECT(std::strcmp(small_id, "00...") == 0);
    format_dhcpv6_client_log_fields(llt.data(), llt.size(), nullptr, 0,
                                    client_mac, sizeof(client_mac));
    EXPECT(std::strcmp(client_mac, "02:aa:bb:cc:dd:ee") == 0);
}

struct old_ipv6_pseudo_header {
    struct in6_addr source;
    struct in6_addr destination;
    uint32_t payload_length;
    uint8_t reserved[3];
    uint8_t next_header;
} __attribute__((packed));

uint32_t old_fold(uint32_t sum)
{
    while (sum >> 16U)
        sum = (sum & UINT16_MAX) + (sum >> 16U);
    return sum;
}

uint32_t old_add(uint32_t sum, const uint8_t *data, size_t len)
{
    while (len >= sizeof(uint16_t)) {
        sum += read_be16(data);
        data += sizeof(uint16_t);
        len -= sizeof(uint16_t);
    }
    if (len != 0)
        sum += static_cast<uint32_t>(data[0]) << CHAR_BIT;
    return old_fold(sum);
}

uint16_t old_checksum(const struct ip6_hdr *ip6h, uint8_t protocol,
                      const uint8_t *data, size_t data_len)
{
    const old_ipv6_pseudo_header pseudo = {
        ip6h->ip6_src,
        ip6h->ip6_dst,
        htonl(static_cast<uint32_t>(data_len)),
        { 0 },
        protocol,
    };
    uint32_t sum = old_add(0, reinterpret_cast<const uint8_t *>(&pseudo),
                           sizeof(pseudo));

    sum = old_add(sum, data, data_len);
    return static_cast<uint16_t>(~old_fold(sum));
}

void test_checksum_equivalence()
{
    std::mt19937 random(0x51a7eU);
    const size_t lengths[] = { 0, 1, 2, 3, 7, 8, 39, 40, 127, 128,
                               255, 256, 1023, 4096, 65535 };

    for (unsigned int round = 0; round < 64U; ++round) {
        struct ip6_hdr ip6h = {};

        for (uint8_t& item : ip6h.ip6_src.s6_addr)
            item = static_cast<uint8_t>(random());
        for (uint8_t& item : ip6h.ip6_dst.s6_addr)
            item = static_cast<uint8_t>(random());

        for (size_t len : lengths) {
            std::vector<uint8_t> payload(len);
            for (uint8_t& item : payload)
                item = static_cast<uint8_t>(random());
            const uint8_t *data = payload.empty() ? nullptr : payload.data();
            EXPECT(icmpv6_checksum(&ip6h, data, len) ==
                   old_checksum(&ip6h, IPPROTO_ICMPV6, data, len));
            EXPECT(udp_ipv6_checksum(&ip6h, data, len) ==
                   old_checksum(&ip6h, IPPROTO_UDP, data, len));
        }
    }
}

std::vector<uint8_t> parser_packet(uint8_t next_header,
                                   const std::vector<uint8_t>& payload)
{
    packet_fixture fixture(next_header, payload);
    return fixture.bytes;
}

std::vector<uint8_t> parser_extension(uint8_t following,
                                      const std::vector<uint8_t>& payload)
{
    std::vector<uint8_t> bytes(8U + payload.size());
    bytes[0] = following;
    bytes[1] = 0;
    std::memcpy(bytes.data() + 8U, payload.data(), payload.size());
    return bytes;
}

void expect_transport(std::vector<uint8_t> bytes,
                      enum ipv6_transport_result result,
                      bool fragmented,
                      Tins::PDU::PDUType type)
{
    ipv6_transport_view view = {};
    EXPECT(parse_ipv6_transport(bytes.data(), bytes.size(), &view) == result);
    EXPECT(view.fragmented == fragmented);
    EXPECT(view.packet_type == type);
}

void test_transport_parser()
{
    ipv6_transport_view view = {};
    uint8_t byte = 0x60;
    EXPECT(parse_ipv6_transport(nullptr, 0, &view) == IPV6_TRANSPORT_MALFORMED);
    EXPECT(parse_ipv6_transport(&byte, 1, nullptr) == IPV6_TRANSPORT_MALFORMED);
    EXPECT(parse_ipv6_transport(&byte,
                                static_cast<size_t>(std::numeric_limits<uint32_t>::max()) + 1U,
                                &view) == IPV6_TRANSPORT_MALFORMED);

    std::vector<uint8_t> ra(sizeof(struct nd_router_advert));
    ra[0] = ND_ROUTER_ADVERT;
    expect_transport(parser_packet(IPPROTO_ICMPV6, ra), IPV6_TRANSPORT_FOUND,
                     false, Tins::PDU::ICMPv6);
    std::vector<uint8_t> echo(8U);
    echo[0] = ICMP6_ECHO_REQUEST;
    expect_transport(parser_packet(IPPROTO_ICMPV6, echo), IPV6_TRANSPORT_FOUND,
                     false, Tins::PDU::UNKNOWN);

    std::vector<uint8_t> udp(sizeof(struct udphdr) + 4U);
    struct udphdr *udp_header = reinterpret_cast<struct udphdr *>(udp.data());
    udp_header->source = htons(547U);
    udp_header->dest = htons(546U);
    udp_header->len = htons(static_cast<uint16_t>(udp.size()));
    expect_transport(parser_packet(IPPROTO_UDP, udp), IPV6_TRANSPORT_FOUND,
                     false, Tins::PDU::DHCPv6);
    udp_header->source = htons(1234U);
    expect_transport(parser_packet(IPPROTO_UDP, udp), IPV6_TRANSPORT_FOUND,
                     false, Tins::PDU::UNKNOWN);
    udp_header->source = htons(547U);
    udp_header->dest = htons(1234U);
    expect_transport(parser_packet(IPPROTO_UDP, udp), IPV6_TRANSPORT_FOUND,
                     false, Tins::PDU::UNKNOWN);

    expect_transport(parser_packet(IPPROTO_HOPOPTS, parser_extension(IPPROTO_ICMPV6, ra)),
                     IPV6_TRANSPORT_FOUND, false, Tins::PDU::ICMPv6);
    expect_transport(parser_packet(IPPROTO_DSTOPTS, parser_extension(IPPROTO_UDP, udp)),
                     IPV6_TRANSPORT_FOUND, false, Tins::PDU::UNKNOWN);
    expect_transport(parser_packet(IPPROTO_ROUTING, parser_extension(IPPROTO_ICMPV6, ra)),
                     IPV6_TRANSPORT_UNSUPPORTED, false, Tins::PDU::UNKNOWN);
    expect_transport(parser_packet(IPPROTO_AH, parser_extension(IPPROTO_ICMPV6, ra)),
                     IPV6_TRANSPORT_UNSUPPORTED, false, Tins::PDU::UNKNOWN);

    std::vector<uint8_t> fragment = parser_extension(IPPROTO_ICMPV6, ra);
    fragment[3] = 1;
    expect_transport(parser_packet(IPPROTO_FRAGMENT, fragment), IPV6_TRANSPORT_FOUND,
                     true, Tins::PDU::UNKNOWN);
    fragment[3] = 8;
    expect_transport(parser_packet(IPPROTO_FRAGMENT, fragment), IPV6_TRANSPORT_FOUND,
                     true, Tins::PDU::UNKNOWN);
    fragment[3] = 0;
    expect_transport(parser_packet(IPPROTO_FRAGMENT, fragment), IPV6_TRANSPORT_UNSUPPORTED,
                     false, Tins::PDU::UNKNOWN);

    expect_transport(parser_packet(IPPROTO_HOPOPTS, { IPPROTO_UDP }),
                     IPV6_TRANSPORT_MALFORMED, false, Tins::PDU::UNKNOWN);
    std::vector<uint8_t> tcp(20U);
    tcp[12] = 5U << 4U;
    expect_transport(parser_packet(IPPROTO_TCP, tcp), IPV6_TRANSPORT_OTHER,
                     false, Tins::PDU::UNKNOWN);
    std::vector<uint8_t> wrong_version = parser_packet(IPPROTO_TCP, tcp);
    wrong_version[0] = 0x50U;
    expect_transport(wrong_version, IPV6_TRANSPORT_OTHER,
                     false, Tins::PDU::UNKNOWN);
    expect_transport(parser_packet(IPPROTO_NONE, {}), IPV6_TRANSPORT_OTHER,
                     false, Tins::PDU::UNKNOWN);
    std::vector<uint8_t> esp(16U);
    expect_transport(parser_packet(IPPROTO_ESP, esp), IPV6_TRANSPORT_UNSUPPORTED,
                     false, Tins::PDU::UNKNOWN);
}

void test_checksum_policy()
{
    packet_fixture ra = router_advertisement(0, {});
    struct nd_router_advert *ra_header = reinterpret_cast<struct nd_router_advert *>(ra.transport.header);
    EXPECT(ra_checksum_state(ra.packet.header, ra.transport.header,
                             ra.transport.len, false) == CHECKSUM_VALID);
    ra_header->nd_ra_cksum ^= htons(1U);
    EXPECT(ra_checksum_state(ra.packet.header, ra.transport.header,
                             ra.transport.len, false) == CHECKSUM_INVALID);
    EXPECT(ra_checksum_state(ra.packet.header, ra.transport.header,
                             ra.transport.len, true) == CHECKSUM_NOT_READY);

    packet_fixture dhcp = dhcpv6_packet(Tins::DHCPv6::REPLY, {});
    struct udphdr *udp = reinterpret_cast<struct udphdr *>(dhcp.transport.header);
    EXPECT(udp_checksum_state(dhcp.packet.header, udp,
                              dhcp.transport.len, false) == CHECKSUM_VALID);
    udp->check = 0;
    EXPECT(udp_checksum_state(dhcp.packet.header, udp,
                              dhcp.transport.len, false) == CHECKSUM_INVALID);
    EXPECT(udp_checksum_state(dhcp.packet.header, udp,
                              dhcp.transport.len, true) == CHECKSUM_NOT_READY);
    udp->check = htons(1U);
    EXPECT(udp_checksum_state(dhcp.packet.header, udp,
                              dhcp.transport.len, false) == CHECKSUM_INVALID);

    EXPECT(preserve_checksum_state(0U, CHECKSUM_VALID, true) == UINT16_MAX);
    EXPECT(preserve_checksum_state(0U, CHECKSUM_VALID, false) == 0U);
    EXPECT(preserve_checksum_state(0x1234U, CHECKSUM_VALID, true) == 0x1234U);
    EXPECT(preserve_checksum_state(0x1234U, CHECKSUM_INVALID, false) == 0x1235U);
    EXPECT(preserve_checksum_state(0U, CHECKSUM_INVALID, true) == (UINT16_MAX ^ 1U));
}

sanitize_result sanitize_ra_fixture(packet_fixture& fixture,
                                   const in6_addr& local_dns,
                                   bool checksum_not_ready,
                                   bool with_log,
                                   char *detail,
                                   char *error)
{
    const std::vector<in6_addr> dns_servers(1U, local_dns);
    std::vector<uint8_t> output;

    fixture.transport.packet_type = Tins::PDU::ICMPv6;
    return sanitize_ra(&fixture.packet, &fixture.transport, dns_servers,
                       checksum_not_ready, with_log ? "from=a to=b" : nullptr,
                       with_log ? detail : nullptr,
                       with_log ? DETAIL_BUFSIZE : 0U,
                       error, ERROR_BUFSIZE, output);
}

void test_ra_malformed_inputs()
{
    const in6_addr local_dns = address("fd00::53");
    char detail[DETAIL_BUFSIZE] = "";
    char error[ERROR_BUFSIZE] = "";
    packet_fixture short_ra(IPPROTO_ICMPV6, std::vector<uint8_t>(sizeof(struct nd_router_advert) - 1U));
    EXPECT(sanitize_ra_fixture(short_ra, local_dns, false, false, detail, error) == SANITIZE_ERROR);
    expect_text_contains(error, "truncated Router Advertisement");

    packet_fixture null_ra = router_advertisement(0, {});
    null_ra.transport.header = nullptr;
    error[0] = '\0';
    EXPECT(sanitize_ra_fixture(null_ra, local_dns, false, false, detail, error) == SANITIZE_ERROR);

    packet_fixture truncated_header = router_advertisement(0, { { 1U } });
    error[0] = '\0';
    EXPECT(sanitize_ra_fixture(truncated_header, local_dns, false, false, detail, error) == SANITIZE_ERROR);
    expect_text_contains(error, "truncated RA option header");

    std::vector<uint8_t> zero = ra_option(1U, 1U);
    zero[1] = 0;
    packet_fixture zero_length = router_advertisement(0, { zero });
    error[0] = '\0';
    EXPECT(sanitize_ra_fixture(zero_length, local_dns, false, false, detail, error) == SANITIZE_ERROR);
    expect_text_contains(error, "zero-length RA option");

    std::vector<uint8_t> overrun = ra_option(1U, 1U);
    overrun[1] = 2U;
    packet_fixture overrun_packet = router_advertisement(0, { overrun });
    error[0] = '\0';
    EXPECT(sanitize_ra_fixture(overrun_packet, local_dns, false, false, detail, error) == SANITIZE_ERROR);
    expect_text_contains(error, "RA option overruns packet");

    packet_fixture short_rdnss = router_advertisement(0,
        { ra_option(Tins::ICMPv6::RECURSIVE_DNS_SERV, 1U) });
    error[0] = '\0';
    EXPECT(sanitize_ra_fixture(short_rdnss, local_dns, false, false, detail, error) == SANITIZE_ERROR);
    expect_text_contains(error, "invalid RDNSS option length");
    packet_fixture odd_rdnss = router_advertisement(0,
        { ra_option(Tins::ICMPv6::RECURSIVE_DNS_SERV, 4U) });
    EXPECT(sanitize_ra_fixture(odd_rdnss, local_dns, false, false, detail, error) == SANITIZE_ERROR);
}

void test_ra_unchanged_and_lifetime()
{
    const in6_addr local_dns = address("fd00::53");
    char detail[DETAIL_BUFSIZE] = "";
    char error[ERROR_BUFSIZE] = "";
    packet_fixture unchanged = router_advertisement(0, {});
    EXPECT(sanitize_ra_fixture(unchanged, local_dns, false, false, detail, error) == SANITIZE_UNCHANGED);

    packet_fixture local_rdnss = router_advertisement(0, { rdnss_option({ local_dns }) });
    EXPECT(sanitize_ra_fixture(local_rdnss, local_dns, false, true, detail, error) == SANITIZE_UNCHANGED);

    packet_fixture changed = router_advertisement(1800U, {});
    EXPECT(sanitize_ra_fixture(changed, local_dns, false, true, detail, error) == SANITIZE_CHANGED);
    struct nd_router_advert *header = reinterpret_cast<struct nd_router_advert *>(changed.transport.header);
    EXPECT(ntohs(header->nd_ra_router_lifetime) == 0U);
    EXPECT(icmpv6_checksum(changed.packet.header, changed.transport.header,
                           changed.transport.len) == 0U);
    expect_text_contains(detail, "router-lifetime=1800->0");

    packet_fixture invalid = router_advertisement(1800U, {}, false);
    EXPECT(sanitize_ra_fixture(invalid, local_dns, false, false, detail, error) == SANITIZE_CHANGED);
    EXPECT(icmpv6_checksum(invalid.packet.header, invalid.transport.header,
                           invalid.transport.len) != 0U);
    packet_fixture not_ready = router_advertisement(1800U, {}, false);
    EXPECT(sanitize_ra_fixture(not_ready, local_dns, true, false, detail, error) == SANITIZE_CHANGED);
    EXPECT(icmpv6_checksum(not_ready.packet.header, not_ready.transport.header,
                           not_ready.transport.len) == 0U);
}

void test_ra_option_rewriting()
{
    const in6_addr local_dns = address("fd00::53");
    const in6_addr remote_one = address("fd00:1::53");
    const in6_addr remote_two = address("fd00:2::53");
    char detail[DETAIL_BUFSIZE] = "";
    char error[ERROR_BUFSIZE] = "";
    packet_fixture fixture = router_advertisement(0,
        { ra_option(1U, 1U, 0x11),
          rdnss_option({ remote_one, remote_two }),
          rdnss_option({ remote_two }),
          ra_option(Tins::ICMPv6::DNS_SEARCH_LIST, 1U),
          ra_option(ND_OPTION_PVD, 1U) }, true, 3U);
    const size_t original_declared = fixture.packet.declared_len;
    const size_t original_captured = fixture.packet.captured_len;
    EXPECT(sanitize_ra_fixture(fixture, local_dns, false, true, detail, error) == SANITIZE_CHANGED);
    EXPECT(fixture.packet.declared_len < original_declared);
    EXPECT(fixture.packet.captured_len < original_captured);
    EXPECT(fixture.packet.captured_len - fixture.packet.declared_len == 3U);
    const uint8_t *options = fixture.transport.header + sizeof(struct nd_router_advert);
    EXPECT(options[0] == 1U);
    const size_t rdnss_offset = NDP_OPTION_LEN_UNIT_OCTETS;
    EXPECT(options[rdnss_offset] == Tins::ICMPv6::RECURSIVE_DNS_SERV);
    EXPECT(options[rdnss_offset + 1U] == 3U);
    EXPECT(std::memcmp(options + rdnss_offset + sizeof(struct rdnss_option_wire),
                       &local_dns, sizeof(local_dns)) == 0);
    expect_text_contains(detail, "rdnss-options=2");
    expect_text_contains(detail, "rdnss-rewritten=1");
    expect_text_contains(detail, "rdnss-deduplicated=2");
    expect_text_contains(detail, "dnssl-removed=1 pvd-removed=1");
}

void test_ra_send_and_compaction_failure()
{
    const in6_addr local_dns = address("fd00::53");
    char detail[DETAIL_BUFSIZE] = "";
    char error[ERROR_BUFSIZE] = "";
    packet_fixture signed_unchanged = router_advertisement(0,
        { ra_option(Tins::ICMPv6::RSA_SIGN, 1U) });
    EXPECT(sanitize_ra_fixture(signed_unchanged, local_dns, false, false,
                               detail, error) == SANITIZE_UNCHANGED);
    packet_fixture signed_changed = router_advertisement(10U,
        { ra_option(Tins::ICMPv6::RSA_SIGN, 1U) });
    EXPECT(sanitize_ra_fixture(signed_changed, local_dns, false, false,
                               detail, error) == SANITIZE_DROP);
    expect_text_contains(error, "SEND-signed RA");

    packet_fixture failure = router_advertisement(0,
        { ra_option(Tins::ICMPv6::DNS_SEARCH_LIST, 1U) });
    failure.packet.header->ip6_plen = 0;
    error[0] = '\0';
    EXPECT(sanitize_ra_fixture(failure, local_dns, false, false,
                               detail, error) == SANITIZE_ERROR);
    expect_text_contains(error, "failed to replace RA options");
}

void test_dhcp_option_parser()
{
    uint8_t bytes[16] = {};
    dhcpv6_option_view view = {};
    char error[ERROR_BUFSIZE] = "";
    EXPECT(dhcpv6_option_parse(bytes + 2, bytes + 1, &view,
                               error, sizeof(error)) == -1);
    expect_text_contains(error, "truncated DHCPv6 option header");
    EXPECT(dhcpv6_option_parse(bytes, bytes + 3, &view,
                               error, sizeof(error)) == -1);

    struct dhcpv6_option_header_wire *header = reinterpret_cast<struct dhcpv6_option_header_wire *>(bytes);
    header->code = htons(23U);
    header->length = htons(20U);
    EXPECT(dhcpv6_option_parse(bytes, bytes + sizeof(bytes), &view,
                               error, sizeof(error)) == -1);
    expect_text_contains(error, "overruns packet");
    header->length = htons(4U);
    EXPECT(dhcpv6_option_parse(bytes, bytes + 8U, &view,
                               error, sizeof(error)) == 0);
    EXPECT(view.code == 23U);
    EXPECT(view.data_len == 4U);
    EXPECT(view.total_len == 8U);
    EXPECT(view.start == bytes);
    EXPECT(view.data == bytes + sizeof(*header));
}

sanitize_result sanitize_dhcp_fixture(packet_fixture& fixture,
                                     const in6_addr& local_dns,
                                     bool checksum_not_ready,
                                     bool with_log,
                                     char *detail,
                                     char *error)
{
    const std::vector<in6_addr> dns_servers(1U, local_dns);
    std::vector<uint8_t> output;

    fixture.transport.packet_type = Tins::PDU::DHCPv6;
    return sanitize_dhcpv6(&fixture.packet, &fixture.transport, dns_servers,
                           checksum_not_ready, with_log ? "from=a to=b" : nullptr,
                           with_log ? detail : nullptr,
                           with_log ? DETAIL_BUFSIZE : 0U,
                           error, ERROR_BUFSIZE, output);
}

void test_dhcp_envelope_validation()
{
    const in6_addr local_dns = address("fd00::53");
    char detail[DETAIL_BUFSIZE] = "";
    char error[ERROR_BUFSIZE] = "";
    packet_fixture fixture = dhcpv6_packet(Tins::DHCPv6::REPLY, {});
    fixture.transport.header = nullptr;
    EXPECT(sanitize_dhcp_fixture(fixture, local_dns, false, false,
                                 detail, error) == SANITIZE_UNCHANGED);
    fixture = dhcpv6_packet(Tins::DHCPv6::REPLY, {});
    fixture.transport.len = sizeof(struct udphdr) - 1U;
    EXPECT(sanitize_dhcp_fixture(fixture, local_dns, false, false,
                                 detail, error) == SANITIZE_UNCHANGED);
    fixture = dhcpv6_packet(Tins::DHCPv6::REPLY, {});
    struct udphdr *udp = reinterpret_cast<struct udphdr *>(fixture.transport.header);
    udp->len = 0;
    EXPECT(sanitize_dhcp_fixture(fixture, local_dns, false, false,
                                 detail, error) == SANITIZE_UNCHANGED);
    udp->len = htons(sizeof(struct udphdr) - 1U);
    EXPECT(sanitize_dhcp_fixture(fixture, local_dns, false, false,
                                 detail, error) == SANITIZE_UNCHANGED);
    udp->len = htons(static_cast<uint16_t>(fixture.transport.len + 1U));
    EXPECT(sanitize_dhcp_fixture(fixture, local_dns, false, false,
                                 detail, error) == SANITIZE_DROP);
    expect_text_contains(error, "exceeds captured transport length");

    std::vector<uint8_t> too_short(sizeof(struct udphdr) + sizeof(struct dhcpv6_direct_header_wire) - 1U);
    udp = reinterpret_cast<struct udphdr *>(too_short.data());
    udp->len = htons(static_cast<uint16_t>(too_short.size()));
    packet_fixture short_dhcp(IPPROTO_UDP, too_short);
    EXPECT(sanitize_dhcp_fixture(short_dhcp, local_dns, false, false,
                                 detail, error) == SANITIZE_UNCHANGED);
    packet_fixture solicit = dhcpv6_packet(Tins::DHCPv6::SOLICIT, {});
    EXPECT(sanitize_dhcp_fixture(solicit, local_dns, false, false,
                                 detail, error) == SANITIZE_UNCHANGED);
}

void test_dhcp_malformed_options()
{
    const in6_addr local_dns = address("fd00::53");
    char detail[DETAIL_BUFSIZE] = "";
    char error[ERROR_BUFSIZE] = "";
    packet_fixture truncated = dhcpv6_packet(Tins::DHCPv6::REPLY, { { 0U, 23U, 0U } });
    EXPECT(sanitize_dhcp_fixture(truncated, local_dns, false, false,
                                 detail, error) == SANITIZE_ERROR);
    expect_text_contains(error, "truncated DHCPv6 option header");

    std::vector<uint8_t> overrun;
    append_be16(overrun, Tins::DHCPv6::DNS_SERVERS);
    append_be16(overrun, 16U);
    overrun.push_back(0U);
    packet_fixture overrun_packet = dhcpv6_packet(Tins::DHCPv6::REPLY, { overrun });
    EXPECT(sanitize_dhcp_fixture(overrun_packet, local_dns, false, false,
                                 detail, error) == SANITIZE_ERROR);
    expect_text_contains(error, "overruns packet");

    packet_fixture empty_dns = dhcpv6_packet(Tins::DHCPv6::REPLY,
        { dhcp_option(Tins::DHCPv6::DNS_SERVERS, {}) });
    EXPECT(sanitize_dhcp_fixture(empty_dns, local_dns, false, false,
                                 detail, error) == SANITIZE_ERROR);
    packet_fixture odd_dns = dhcpv6_packet(Tins::DHCPv6::REPLY,
        { dhcp_option(Tins::DHCPv6::DNS_SERVERS, { 1U }) });
    EXPECT(sanitize_dhcp_fixture(odd_dns, local_dns, false, false,
                                 detail, error) == SANITIZE_ERROR);
}

void test_dhcp_unchanged_and_rewrite()
{
    const in6_addr local_dns = address("fd00::53");
    const in6_addr remote_one = address("fd00:1::53");
    const in6_addr remote_two = address("fd00:2::53");
    char detail[DETAIL_BUFSIZE] = "";
    char error[ERROR_BUFSIZE] = "";
    packet_fixture unchanged = dhcpv6_packet(Tins::DHCPv6::ADVERTISE,
        { dhcp_option(1U, { 0U, 1U }),
          dhcp_option(Tins::DHCPv6::DNS_SERVERS, wire_addresses({ local_dns })) });
    EXPECT(sanitize_dhcp_fixture(unchanged, local_dns, false, true,
                                 detail, error) == SANITIZE_UNCHANGED);

    const std::vector<uint8_t> client_duid = {
        0x00, 0x03, 0x00, 0x01, 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
    };
    packet_fixture changed = dhcpv6_packet(Tins::DHCPv6::REPLY,
        { dhcp_option(Tins::DHCPv6::CLIENTID, client_duid),
          dhcp_option(Tins::DHCPv6::DNS_SERVERS, wire_addresses({ remote_one, remote_two })),
          dhcp_option(Tins::DHCPv6::DNS_SERVERS, wire_addresses({ remote_two })),
          dhcp_option(Tins::DHCPv6::DOMAIN_LIST, { 3U, 'l', 'a', 'n', 0U }) },
        true, 2U);
    const size_t original_declared = changed.packet.declared_len;
    EXPECT(sanitize_dhcp_fixture(changed, local_dns, false, true,
                                 detail, error) == SANITIZE_CHANGED);
    EXPECT(changed.packet.declared_len < original_declared);
    EXPECT(changed.packet.captured_len - changed.packet.declared_len == 2U);
    struct udphdr *udp = reinterpret_cast<struct udphdr *>(changed.transport.header);
    EXPECT(ntohs(udp->len) == changed.packet.declared_len - sizeof(struct ip6_hdr));
    EXPECT(udp_ipv6_checksum(changed.packet.header,
                             changed.transport.header, ntohs(udp->len)) == 0U);
    expect_text_contains(detail, "type=DHCPv6-Reply");
    expect_text_contains(detail, "client-mac=02:aa:bb:cc:dd:ee");
    expect_text_contains(detail, "dns-options=2");
    expect_text_contains(detail, "dns-rewritten=1");
    expect_text_contains(detail, "dns-deduplicated=2");
    expect_text_contains(detail, "domain-search-removed=1");
}

void test_dhcp_authentication_and_checksum()
{
    const in6_addr local_dns = address("fd00::53");
    const in6_addr remote_dns = address("fd00:1::53");
    char detail[DETAIL_BUFSIZE] = "";
    char error[ERROR_BUFSIZE] = "";
    packet_fixture auth_unchanged = dhcpv6_packet(Tins::DHCPv6::REPLY,
        { dhcp_option(Tins::DHCPv6::AUTH, { 1U }) });
    EXPECT(sanitize_dhcp_fixture(auth_unchanged, local_dns, false, false,
                                 detail, error) == SANITIZE_UNCHANGED);
    packet_fixture auth_changed = dhcpv6_packet(Tins::DHCPv6::REPLY,
        { dhcp_option(Tins::DHCPv6::AUTH, { 1U }),
          dhcp_option(Tins::DHCPv6::DNS_SERVERS, wire_addresses({ remote_dns })) });
    EXPECT(sanitize_dhcp_fixture(auth_changed, local_dns, false, false,
                                 detail, error) == SANITIZE_DROP);
    expect_text_contains(error, "authenticated DHCPv6");

    packet_fixture invalid = dhcpv6_packet(Tins::DHCPv6::REPLY,
        { dhcp_option(Tins::DHCPv6::DNS_SERVERS, wire_addresses({ remote_dns })) }, false);
    EXPECT(sanitize_dhcp_fixture(invalid, local_dns, false, false,
                                 detail, error) == SANITIZE_CHANGED);
    struct udphdr *udp = reinterpret_cast<struct udphdr *>(invalid.transport.header);
    EXPECT(udp_ipv6_checksum(invalid.packet.header, invalid.transport.header,
                             ntohs(udp->len)) != 0U);
    packet_fixture not_ready = dhcpv6_packet(Tins::DHCPv6::REPLY,
        { dhcp_option(Tins::DHCPv6::DNS_SERVERS, wire_addresses({ remote_dns })) }, false);
    EXPECT(sanitize_dhcp_fixture(not_ready, local_dns, true, false,
                                 detail, error) == SANITIZE_CHANGED);
    udp = reinterpret_cast<struct udphdr *>(not_ready.transport.header);
    EXPECT(udp_ipv6_checksum(not_ready.packet.header, not_ready.transport.header,
                             ntohs(udp->len)) == 0U);

    packet_fixture failure = dhcpv6_packet(Tins::DHCPv6::REPLY,
        { dhcp_option(Tins::DHCPv6::DOMAIN_LIST, { 1U }) });
    failure.packet.header->ip6_plen = 0;
    EXPECT(sanitize_dhcp_fixture(failure, local_dns, false, false,
                                 detail, error) == SANITIZE_ERROR);
    expect_text_contains(error, "failed to replace DHCPv6 options");
}

int call_packet_cb(nfgenmsg *message, app_ctx *ctx)
{
    // Simulate cache maintenance by the event loop, not by the callback.
    static unsigned int tick = 0;
    if (ctx->dns_servers.empty())
        ctx->dns_cache.refresh(local_dns_cache::clock::time_point{} +
                               std::chrono::seconds(++tick * 5U));
    return packet_cb(reinterpret_cast<struct nfq_q_handle *>(1), message,
                     reinterpret_cast<struct nfq_data *>(1), ctx);
}

void test_callback_envelope_policy()
{
    reset_stubs();
    app_ctx ctx = {};
    nfgenmsg message = bridge_message();
    nfq_stub.header_available = false;
    EXPECT(call_packet_cb(&message, &ctx) == -1);
    EXPECT(nfq_stub.verdicts.empty());

    reset_stubs();
    EXPECT(call_packet_cb(nullptr, &ctx) == 0);
    expect_last_verdict(NF_ACCEPT, 0U);
    reset_stubs();
    message.nfgen_family = AF_INET6;
    ctx.verbose = true;
    EXPECT(call_packet_cb(&message, &ctx) == 0);
    expect_last_verdict(NF_ACCEPT, 0U);

    reset_stubs();
    message = bridge_message();
    nfq_stub.payload_len = 0;
    EXPECT(call_packet_cb(&message, &ctx) == 0);
    expect_last_verdict(NF_ACCEPT, 0U);
    reset_stubs();
    nfq_stub.payload_len = 1;
    nfq_stub.payload = nullptr;
    EXPECT(call_packet_cb(&message, &ctx) == 0);
    expect_last_verdict(NF_ACCEPT, 0U);
    reset_stubs();
    std::vector<uint8_t> byte(1U, 0x60U);
    nfq_stub.payload = byte.data();
    nfq_stub.payload_len = 1;
    EXPECT(call_packet_cb(&message, &ctx) == 0);
    expect_last_verdict(NF_ACCEPT, 0U);

    reset_stubs();
    packet_fixture truncated(IPPROTO_NONE, { 1U });
    truncated.packet.header->ip6_plen = htons(100U);
    prepare_callback_payload(truncated.bytes);
    EXPECT(call_packet_cb(&message, &ctx) == 0);
    expect_last_verdict(NF_DROP, 0U);
}

void test_callback_transport_policy()
{
    app_ctx ctx = {};
    nfgenmsg message = bridge_message();
    reset_stubs();
    std::vector<uint8_t> tcp(20U);
    tcp[12] = 5U << 4U;
    packet_fixture other(IPPROTO_TCP, tcp);
    prepare_callback_payload(other.bytes);
    EXPECT(call_packet_cb(&message, &ctx) == 0);
    expect_last_verdict(NF_ACCEPT, 0U);

    reset_stubs();
    std::vector<uint8_t> fragment = parser_extension(IPPROTO_ICMPV6,
                                                    std::vector<uint8_t>(sizeof(struct nd_router_advert)));
    fragment[3] = 1U;
    packet_fixture fragmented(IPPROTO_FRAGMENT, fragment);
    prepare_callback_payload(fragmented.bytes);
    EXPECT(call_packet_cb(&message, &ctx) == 0);
    expect_last_verdict(NF_DROP, 0U);

    reset_stubs();
    std::vector<uint8_t> echo(8U);
    echo[0] = ICMP6_ECHO_REQUEST;
    packet_fixture unknown(IPPROTO_ICMPV6, echo);
    prepare_callback_payload(unknown.bytes);
    EXPECT(call_packet_cb(&message, &ctx) == 0);
    expect_last_verdict(NF_ACCEPT, 0U);

    reset_stubs();
    packet_fixture ra = router_advertisement(10U, {});
    prepare_callback_payload(ra.bytes);
    resolver_result = -1;
    app_ctx never_cached = {};
    EXPECT(call_packet_cb(&message, &never_cached) == 0);
    expect_last_verdict(NF_ACCEPT, 0U);
}

void test_callback_sanitizer_results()
{
    app_ctx ctx = {};
    nfgenmsg message = bridge_message();
    reset_stubs();
    packet_fixture unchanged = router_advertisement(0, {});
    prepare_callback_payload(unchanged.bytes);
    EXPECT(call_packet_cb(&message, &ctx) == 0);
    expect_last_verdict(NF_ACCEPT, 0U);

    reset_stubs();
    packet_fixture malformed = router_advertisement(0,
        { ra_option(Tins::ICMPv6::RECURSIVE_DNS_SERV, 1U) });
    prepare_callback_payload(malformed.bytes);
    EXPECT(call_packet_cb(&message, &ctx) == 0);
    expect_last_verdict(NF_ACCEPT, 0U);

    reset_stubs();
    packet_fixture drop = router_advertisement(10U,
        { ra_option(Tins::ICMPv6::RSA_SIGN, 1U) });
    prepare_callback_payload(drop.bytes);
    EXPECT(call_packet_cb(&message, &ctx) == 0);
    expect_last_verdict(NF_DROP, 0U);

    reset_stubs();
    ctx.verbose = true;
    packet_fixture changed = router_advertisement(10U, {});
    const size_t changed_size = changed.bytes.size();
    prepare_callback_payload(changed.bytes);
    EXPECT(call_packet_cb(&message, &ctx) == 0);
    expect_last_verdict(NF_ACCEPT, static_cast<uint32_t>(changed_size));
    EXPECT(!nfq_stub.verdicts.back().data.empty());

    reset_stubs();
    ctx.verbose = false;
    packet_fixture dhcp = dhcpv6_packet(Tins::DHCPv6::REPLY,
        { dhcp_option(Tins::DHCPv6::DOMAIN_LIST, { 1U }) });
    prepare_callback_payload(dhcp.bytes);
    nfq_stub.skbinfo = NFQA_SKB_CSUMNOTREADY;
    EXPECT(call_packet_cb(&message, &ctx) == 0);
    EXPECT(!nfq_stub.verdicts.empty());
    EXPECT(nfq_stub.verdicts[0].data_len != 0U);

    reset_stubs();
    changed = router_advertisement(10U, {});
    prepare_callback_payload(changed.bytes);
    nfq_stub.modified_verdict_result = -1;
    EXPECT(call_packet_cb(&message, &ctx) == 0);
    EXPECT(nfq_stub.verdicts.size() == 2U);
    EXPECT(nfq_stub.verdicts[0].data_len != 0U);
    EXPECT(nfq_stub.verdicts[1].data_len == 0U);
}


void test_verdict_memory_boundaries()
{
    for (size_t length : { 1U, 2U, 3U, 4U, 65530U, 65531U, 65532U }) {
        reset_stubs();
        std::vector<uint8_t> bytes(length, 0xa5);
        ipv6_packet_view packet = {};
        packet.data = bytes.data();
        packet.captured_len = bytes.size();

        std::vector<uint8_t> output;
        const int result = verdict_with_modified_ipv6(nullptr, 42U, &packet, output);
        if (length > 65531U) {
            EXPECT(result == -1);
            EXPECT(errno == EMSGSIZE);
            EXPECT(nfq_stub.verdicts.empty());
        } else {
            EXPECT(result == 0);
            EXPECT(nfq_stub.verdicts.back().data == bytes);
        }
    }

    // Growth is valid IPv6 but too large for a netlink payload attribute.
    reset_stubs();
    app_ctx ctx = {};
    ctx.dns_servers.assign(10U, address("fd00::53"));
    nfgenmsg message = bridge_message();
    std::vector<std::vector<uint8_t>> options = {
        rdnss_option({ address("fd00::1") })
    };
    for (size_t remaining = 65320U; remaining != 0;) {
        const size_t length = std::min(remaining, size_t(2040U));
        options.push_back(ra_option(1U, static_cast<uint8_t>(length / 8U)));
        remaining -= length;
    }
    auto packet = router_advertisement(0, options);
    EXPECT(packet.bytes.size() == 65400U);
    prepare_callback_payload(packet.bytes);
    EXPECT(call_packet_cb(&message, &ctx) == 0);
    EXPECT(nfq_stub.verdicts.size() == 1U);
    expect_last_verdict(NF_ACCEPT, 0U);
}

void test_callback_allocation_failures()
{
    app_ctx ctx = {};
    ctx.verbose = true;
    ctx.dns_servers = { address("fd00::53"), address("fd00::54") };
    nfgenmsg message = bridge_message();
    bool completed = false;
    unsigned int failures = 0;

    for (int budget = 0; budget < 128; ++budget) {
        reset_stubs();
        auto packet = router_advertisement(10,
            { rdnss_option({ address("fd00::1") }) });
        prepare_callback_payload(packet.bytes);
        allocation_failed = false;
        allocations_before_failure = budget;
        const int result = call_packet_cb(&message, &ctx);
        allocations_before_failure = -1;

        EXPECT(result == 0);
        EXPECT(nfq_stub.verdicts.size() == 1U);
        if (allocation_failed) {
            ++failures;
            expect_last_verdict(NF_ACCEPT, 0U);
        } else {
            EXPECT(nfq_stub.verdicts.back().data_len != 0U);
            completed = true;
            break;
        }
    }
    EXPECT(failures > 2U);
    EXPECT(completed);
}


void test_dns_cache()
{
    reset_stubs();
    current_readlink_mode = READLINK_TEXT;
    readlink_text = "/sys/class/net/br-lan";
    std::string path;
    const auto start = local_dns_cache::clock::time_point{};
    {
        local_dns_cache cache;
        cache.refresh(start);
        EXPECT(discovery_calls == 1U && discovery_frees == 1U);
        const auto *bridge = cache.find(11, 0);
        const auto *port = cache.find(12, 0);
        EXPECT(bridge != nullptr && port != nullptr);
        EXPECT(bridge->description == "fd00::53(br-lan)");
        EXPECT(port->description == bridge->description);
        EXPECT(cache.find(999, 12) == port);
        EXPECT(cache.find(0, 0) == nullptr);

        path = cache.path();
        struct stat metadata = {};
        EXPECT(stat(path.c_str(), &metadata) == 0);
        EXPECT((metadata.st_mode & 0777) == 0600);
        FILE *snapshot = fopen(path.c_str(), "r");
        EXPECT(snapshot != nullptr);
        char contents[256] = {};
        EXPECT(fread(contents, 1, sizeof(contents) - 1U, snapshot) != 0);
        fclose(snapshot);
        expect_text_contains(contents, "11 fd00::53(br-lan)");
        expect_text_contains(contents, "12 fd00::53(br-lan)");

        for (unsigned int i = 0; i < 1000U; ++i)
            EXPECT(cache.find(12, 0) == port);
        cache.refresh(start + std::chrono::seconds(4));
        EXPECT(discovery_calls == 1U);

        // Missing addresses keep the previous DNS and persisted snapshot while retrying.
        network_address.sin6_addr = address("fe80::1");
        cache.refresh(start + std::chrono::seconds(5));
        EXPECT(cache.find(11, 12)->description == "fd00::53(br-lan)");
        EXPECT(stat(path.c_str(), &metadata) == 0 && metadata.st_size > 0);
        EXPECT(cache_writes == 1U);
        network_address.sin6_addr = address("fc00::99");
        cache.refresh(start + std::chrono::seconds(10));
        EXPECT(cache.find(11, 0)->description == "fc00::99(br-lan)");

        resolver_result = -1;
        cache.refresh(start + std::chrono::seconds(15));
        EXPECT(cache.find(11, 12)->description == "fc00::99(br-lan)");
        EXPECT(access(path.c_str(), F_OK) == 0);
        resolver_result = 0;
        cache.refresh(start + std::chrono::seconds(19));
        EXPECT(cache.find(11, 12)->description == "fc00::99(br-lan)");
        cache.refresh(start + std::chrono::seconds(20));
        EXPECT(cache.find(11, 12) != nullptr);
        path = cache.path();

        // Interface deletion/recreation must not retain the previous address.
        network_links[0].sll_ifindex = 21;
        sockaddr_in6 direct = network_address;
        direct.sin6_addr = address("fd00::77");
        network_rows[2].ifa_next = &network_rows[3];
        network_rows[3].ifa_name = const_cast<char *>("vxlan0");
        network_rows[3].ifa_addr = reinterpret_cast<sockaddr *>(&direct);
        cache.refresh(start + std::chrono::seconds(25));
        EXPECT(cache.find(12, 21)->description == "fd00::77(vxlan0)");
        EXPECT(cache.find(21, 12)->description == "fc00::99(br-lan)");
        EXPECT(cache.find(11, 0) == nullptr);
        EXPECT(cache.find(21, 0) != nullptr);

        network_rows[0].ifa_name = const_cast<char *>("new-interface");
        network_rows[1].ifa_name = const_cast<char *>("new-interface");
        network_address.sin6_addr = address("fe80::1");
        cache.refresh(start + std::chrono::seconds(30));
        EXPECT(cache.find(21, 0) == nullptr);
    }
    EXPECT(access(path.c_str(), F_OK) == -1);

    reset_stubs();
    local_dns_cache cache;
    cache_file_failure = true;
    cache.refresh(start);
    EXPECT(cache.find(11, 0) != nullptr);
    EXPECT(cache.path()[0] == '\0');
    cache_file_failure = false;
    cache.refresh(start + std::chrono::seconds(5));
    EXPECT(cache.path()[0] != '\0');

    // Discovery allocation failure frees getifaddrs but preserves the last DNS.
    allocations_before_failure = 0;
    cache.refresh(start + std::chrono::seconds(10));
    allocations_before_failure = -1;
    EXPECT(cache.find(11, 0)->description == "fd00::53(br-lan)");
    EXPECT(discovery_calls == discovery_frees);
    cache.refresh(start + std::chrono::seconds(15));
    EXPECT(cache.find(11, 0) != nullptr);
    const unsigned int writes = cache_writes;
    cache.refresh(start + std::chrono::seconds(20));
    EXPECT(cache_writes == writes);

    cache_write_failure = true;
    network_address.sin6_addr = address("fd00::88");
    cache.refresh(start + std::chrono::seconds(25));
    EXPECT(cache.find(11, 0)->description == "fd00::88(br-lan)");
    EXPECT(cache.path()[0] == '\0');
    cache_write_failure = false;
    cache.refresh(start + std::chrono::seconds(30));
    EXPECT(cache.path()[0] != '\0');
}

void test_callback_cache_and_buffer_reuse()
{
    reset_stubs();
    app_ctx ctx = {};
    ctx.dns_cache.refresh();
    nfgenmsg message = bridge_message();
    auto input = router_advertisement(10, { rdnss_option({ address("fd00::1") }) });
    const auto original = input.bytes;
    prepare_callback_payload(input.bytes);
    const auto call = [&]() {
        return packet_cb(reinterpret_cast<nfq_q_handle *>(1), &message,
                         reinterpret_cast<nfq_data *>(1), &ctx);
    };
    EXPECT(call() == 0);
    const auto *buffer = ctx.packet_buffer.data();
    const auto *options = ctx.option_buffer.data();
    for (unsigned int i = 0; i < 100U; ++i) {
        std::copy(original.begin(), original.end(), input.bytes.begin());
        nfq_stub.verdicts.clear();
        EXPECT(call() == 0);
        EXPECT(nfq_stub.verdicts.back().data_len != 0U);
        EXPECT(ctx.packet_buffer.data() == buffer);
        EXPECT(ctx.option_buffer.data() == options);
    }
    EXPECT(discovery_calls == 1U && discovery_frees == 1U);

    resolver_result = -1;
    ctx.dns_cache.refresh(local_dns_cache::clock::now() + std::chrono::seconds(5));
    std::copy(original.begin(), original.end(), input.bytes.begin());
    nfq_stub.verdicts.clear();
    EXPECT(call() == 0);
    EXPECT(nfq_stub.verdicts.back().data_len != 0U);
    const auto expected = router_advertisement(0,
        { rdnss_option({ address("fd00::53") }) });
    EXPECT(nfq_stub.verdicts.back().data == expected.bytes);

    // Validation failures leave the source untouched, even after a DNS option.
    char detail[DETAIL_BUFSIZE] = {};
    char error[ERROR_BUFSIZE] = {};
    auto malformed = router_advertisement(10,
        { rdnss_option({ address("fd00::1") }), { 1 } });
    const auto original_malformed = malformed.bytes;
    EXPECT(sanitize_ra_fixture(malformed, address("fd00::53"), false, false,
                               detail, error) == SANITIZE_ERROR);
    EXPECT(malformed.bytes == original_malformed);
    auto malformed_dhcp = dhcpv6_packet(Tins::DHCPv6::REPLY,
        { dhcp_option(Tins::DHCPv6::DNS_SERVERS,
                      wire_addresses({ address("fd00::1") })), { 1 } });
    const auto original_dhcp = malformed_dhcp.bytes;
    EXPECT(sanitize_dhcp_fixture(malformed_dhcp, address("fd00::53"), false, false,
                                 detail, error) == SANITIZE_ERROR);
    EXPECT(malformed_dhcp.bytes == original_dhcp);
}

void test_callback_configured_dns_servers()
{
    app_ctx ctx = {};
    const in6_addr primary_dns = address("fd00::53");
    const in6_addr secondary_dns = address("2001:db8::53");
    ctx.dns_servers = { primary_dns, secondary_dns };
    nfgenmsg message = bridge_message();

    // Exercise growth, shrinkage and equal-sized replacement with later options
    // and captured trailers. Compare the complete verdict, including checksums.
    for (const auto& incoming : std::vector<std::vector<in6_addr>>{
             { primary_dns }, { primary_dns, secondary_dns },
             { primary_dns, secondary_dns, address("fd00::99") } }) {
        reset_stubs();
        auto input_ra = router_advertisement(0,
            { rdnss_option(incoming), ra_option(1U, 1U, 0x11) }, true, 3U);
        auto expected_ra = router_advertisement(0,
            { rdnss_option(ctx.dns_servers), ra_option(1U, 1U, 0x11) }, true, 3U);
        prepare_callback_payload(input_ra.bytes);
        EXPECT(call_packet_cb(&message, &ctx) == 0);
        const auto& ra_verdict = nfq_stub.verdicts.back();
        EXPECT((ra_verdict.data.empty() ? input_ra.bytes : ra_verdict.data) == expected_ra.bytes);

        reset_stubs();
        auto input_dhcp = dhcpv6_packet(Tins::DHCPv6::REPLY,
            { dhcp_option(Tins::DHCPv6::DNS_SERVERS, wire_addresses(incoming)),
              dhcp_option(Tins::DHCPv6::CLIENTID, { 1, 2, 3 }) }, true, 3U);
        auto expected_dhcp = dhcpv6_packet(Tins::DHCPv6::REPLY,
            { dhcp_option(Tins::DHCPv6::DNS_SERVERS, wire_addresses(ctx.dns_servers)),
              dhcp_option(Tins::DHCPv6::CLIENTID, { 1, 2, 3 }) }, true, 3U);
        prepare_callback_payload(input_dhcp.bytes);
        EXPECT(call_packet_cb(&message, &ctx) == 0);
        const auto& dhcp_verdict = nfq_stub.verdicts.back();
        EXPECT((dhcp_verdict.data.empty() ? input_dhcp.bytes : dhcp_verdict.data) == expected_dhcp.bytes);
    }

    reset_stubs();
    packet_fixture ra = router_advertisement(0,
        { rdnss_option({ address("fd00:1::53") }) });
    const size_t original_ra_size = ra.bytes.size();
    prepare_callback_payload(ra.bytes);
    resolver_result = -1;
    EXPECT(call_packet_cb(&message, &ctx) == 0);
    expect_last_verdict(
        NF_ACCEPT,
        static_cast<uint32_t>(original_ra_size + sizeof(struct in6_addr))
    );
    const std::vector<uint8_t>& modified_ra = nfq_stub.verdicts.back().data;
    const size_t rdnss_offset =
        sizeof(struct ip6_hdr) + sizeof(struct nd_router_advert);
    EXPECT(modified_ra[rdnss_offset + 1U] == 5U);
    EXPECT(std::memcmp(
        modified_ra.data() + rdnss_offset + sizeof(struct rdnss_option_wire),
        &primary_dns,
        sizeof(primary_dns)
    ) == 0);
    EXPECT(std::memcmp(
        modified_ra.data() + rdnss_offset + sizeof(struct rdnss_option_wire) +
            sizeof(struct in6_addr),
        &secondary_dns,
        sizeof(secondary_dns)
    ) == 0);
    const struct ip6_hdr *ra_ip6h =
        reinterpret_cast<const struct ip6_hdr *>(modified_ra.data());
    EXPECT(icmpv6_checksum(
        ra_ip6h,
        modified_ra.data() + sizeof(struct ip6_hdr),
        modified_ra.size() - sizeof(struct ip6_hdr)
    ) == 0U);

    reset_stubs();
    packet_fixture dhcp = dhcpv6_packet(Tins::DHCPv6::REPLY,
        { dhcp_option(
            Tins::DHCPv6::DNS_SERVERS,
            wire_addresses({ address("fd00:1::53") })
        ) });
    const size_t original_dhcp_size = dhcp.bytes.size();
    prepare_callback_payload(dhcp.bytes);
    resolver_result = -1;
    EXPECT(call_packet_cb(&message, &ctx) == 0);
    expect_last_verdict(
        NF_ACCEPT,
        static_cast<uint32_t>(original_dhcp_size + sizeof(struct in6_addr))
    );
    const std::vector<uint8_t>& modified_dhcp = nfq_stub.verdicts.back().data;
    const size_t dns_option_offset =
        sizeof(struct ip6_hdr) + sizeof(struct udphdr) +
        sizeof(struct dhcpv6_direct_header_wire);
    EXPECT(read_be16(modified_dhcp.data() + dns_option_offset) ==
           Tins::DHCPv6::DNS_SERVERS);
    EXPECT(read_be16(modified_dhcp.data() + dns_option_offset + sizeof(uint16_t)) ==
           2U * sizeof(struct in6_addr));
    EXPECT(std::memcmp(
        modified_dhcp.data() + dns_option_offset +
            sizeof(struct dhcpv6_option_header_wire),
        &primary_dns,
        sizeof(primary_dns)
    ) == 0);
    EXPECT(std::memcmp(
        modified_dhcp.data() + dns_option_offset +
            sizeof(struct dhcpv6_option_header_wire) + sizeof(struct in6_addr),
        &secondary_dns,
        sizeof(secondary_dns)
    ) == 0);
    const struct ip6_hdr *dhcp_ip6h =
        reinterpret_cast<const struct ip6_hdr *>(modified_dhcp.data());
    const struct udphdr *udp = reinterpret_cast<const struct udphdr *>(
        modified_dhcp.data() + sizeof(struct ip6_hdr)
    );
    EXPECT(udp_ipv6_checksum(
        dhcp_ip6h,
        reinterpret_cast<const uint8_t *>(udp),
        ntohs(udp->len)
    ) == 0U);
}

int run_daemon(std::vector<std::string> arguments)
{
    std::vector<char *> argv;
    for (std::string& item : arguments)
        argv.push_back(&item[0]);
    argv.push_back(nullptr);
    optind = 1;
    opterr = 0;
    return bridge_ipv6_dns_sanitizer_daemon_main(static_cast<int>(arguments.size()), argv.data());
}

std::string capture_daemon_stdout(
    std::vector<std::string> arguments,
    int& status)
{
    std::string output;
    char buffer[256];

    fflush(stdout);
    FILE *capture = tmpfile();
    EXPECT(capture != nullptr);
    if (capture == nullptr)
        return output;

    const int saved_stdout = dup(STDOUT_FILENO);
    EXPECT(saved_stdout >= 0);
    if (saved_stdout < 0) {
        fclose(capture);
        return output;
    }

    EXPECT(dup2(fileno(capture), STDOUT_FILENO) >= 0);
    status = run_daemon(arguments);
    fflush(stdout);
    EXPECT(dup2(saved_stdout, STDOUT_FILENO) >= 0);
    close(saved_stdout);

    EXPECT(fseek(capture, 0, SEEK_SET) == 0);
    while (fgets(buffer, sizeof(buffer), capture) != nullptr)
        output += buffer;
    fclose(capture);
    return output;
}

void test_queue_number_parsing()
{
    uint16_t queue_number = 0;
    in6_addr dns_server = {};
    const in6_addr expected_dns = address("fd00::53");

    EXPECT(parse_queue_number("0", &queue_number));
    EXPECT(queue_number == 0U);
    EXPECT(parse_queue_number("65535", &queue_number));
    EXPECT(queue_number == 65535U);
    EXPECT(parse_queue_number("+1", &queue_number));
    EXPECT(queue_number == 1U);
    EXPECT(parse_queue_number(" 2", &queue_number));
    EXPECT(queue_number == 2U);
    EXPECT(!parse_queue_number(nullptr, &queue_number));
    EXPECT(!parse_queue_number("", &queue_number));
    EXPECT(!parse_queue_number("-1", &queue_number));
    EXPECT(!parse_queue_number("1x", &queue_number));
    EXPECT(!parse_queue_number("65536", &queue_number));
    EXPECT(!parse_queue_number("1", nullptr));
    EXPECT(parse_dns_server("fd00::53", &dns_server));
    EXPECT(std::memcmp(&dns_server, &expected_dns, sizeof(dns_server)) == 0);
    EXPECT(!parse_dns_server("192.0.2.53", &dns_server));
    EXPECT(!parse_dns_server("invalid", &dns_server));
    EXPECT(!parse_dns_server(nullptr, &dns_server));
}

void test_startup_logging()
{
    reset_stubs();
    running = 0;
    int status = EXIT_FAILURE;
    const std::string output = capture_daemon_stdout(
        { "daemon", "-q", "321", "-d", "fd00::53", "-d", "2001:db8::53" },
        status);

    EXPECT(status == EXIT_SUCCESS);
    expect_text_contains(output.c_str(),
                         "starting version " BRIDGE_IPV6_DNS_SANITIZER_VERSION "\n");
    expect_text_contains(output.c_str(), "listening on NFQUEUE 321\n");
    expect_text_contains(output.c_str(),
                         "using 2 configured DNS server(s)\n");
    EXPECT(nfq_stub.queue_number == 321U);
    EXPECT(nfq_stub.configured_dns_log == "configured(2)");
    expect_text_contains(output.c_str(), "stopping\n");
    expect_text_contains(output.c_str(), "exiting\n");
    EXPECT(output.find("bridge-ipv6-dns-sanitizer:") == std::string::npos);

    reset_stubs();
    std::vector<std::string> arguments = { "daemon", "-q", "100", "-v" };
    for (unsigned int i = 0; i < 10U; ++i) {
        arguments.push_back("-d");
        arguments.push_back("fd00::53");
    }
    EXPECT(run_daemon(arguments) == EXIT_SUCCESS);
    EXPECT(nfq_stub.configured_dns_log == "configured(10)");
}

void test_signal_and_cli_paths()
{
    reset_stubs();
    running = 1;
    handle_signal(SIGTERM);
    EXPECT(running == 0);
    sigaction_fail_call = 1;
    EXPECT(install_signal_handlers() == -1);
    sigaction_calls = 0;
    sigaction_fail_call = 2;
    EXPECT(install_signal_handlers() == -1);
    sigaction_calls = 0;
    sigaction_fail_call = 0;
    EXPECT(install_signal_handlers() == 0);
    EXPECT(sigaction_calls == 2);

    std::vector<std::string> too_many_dns_servers = { "daemon", "-q", "100" };
    for (size_t dns_server_count = 0; dns_server_count < 11U; dns_server_count++) {
        too_many_dns_servers.push_back("-d");
        too_many_dns_servers.push_back("fd00::53");
    }

    EXPECT(run_daemon({ "daemon", "-h" }) == EXIT_SUCCESS);
    EXPECT(run_daemon({ "daemon" }) == EXIT_FAILURE);
    EXPECT(run_daemon({ "daemon", "-q", "100", "-d", "invalid" }) == EXIT_FAILURE);
    EXPECT(run_daemon(too_many_dns_servers) == EXIT_FAILURE);
    EXPECT(run_daemon({ "daemon", "-q" }) == EXIT_FAILURE);
    EXPECT(run_daemon({ "daemon", "-q", "invalid" }) == EXIT_FAILURE);
    EXPECT(run_daemon({ "daemon", "-q", "65536" }) == EXIT_FAILURE);
    EXPECT(run_daemon({ "daemon", "-q", "100", "extra" }) == EXIT_FAILURE);
    EXPECT(run_daemon({ "daemon", "-x" }) == EXIT_FAILURE);
}

void test_daemon_setup_failures()
{
    reset_stubs();
    sigaction_fail_call = 1;
    EXPECT(run_daemon({ "daemon", "-q", "100" }) == EXIT_FAILURE);
    EXPECT(nfq_stub.close_calls == 0);

    reset_stubs();
    nfq_stub.open_succeeds = false;
    EXPECT(run_daemon({ "daemon", "-q", "100" }) == EXIT_FAILURE);
    reset_stubs();
    nfq_stub.create_queue_succeeds = false;
    EXPECT(run_daemon({ "daemon", "-q", "100" }) == EXIT_FAILURE);
    EXPECT(nfq_stub.close_calls == 1);

    reset_stubs();
    nfq_stub.queue_flags_result = -1;
    EXPECT(run_daemon({ "daemon", "-q", "100" }) == EXIT_FAILURE);
    EXPECT(nfq_stub.destroy_calls == 1 && nfq_stub.close_calls == 1);
    reset_stubs();
    nfq_stub.mode_result = -1;
    EXPECT(run_daemon({ "daemon", "-q", "100" }) == EXIT_FAILURE);
    EXPECT(nfq_stub.destroy_calls == 1 && nfq_stub.close_calls == 1);

    reset_stubs();
    nfq_stub.maxlen_result = -1;
    running = 0;
    EXPECT(run_daemon({ "daemon", "-q", "100", "-v" }) == EXIT_SUCCESS);
    EXPECT(nfq_stub.destroy_calls == 1 && nfq_stub.close_calls == 1);
}

void run_loop_case(const poll_step& poll_value,
                   const std::vector<recv_step>& receive_values,
                   int handle_result,
                   int expected_status)
{
    reset_stubs();
    poll_steps.push_back(poll_value);
    recv_steps = receive_values;
    nfq_stub.handle_packet_result = handle_result;
    running = 1;
    EXPECT(run_daemon({ "daemon", "-q", "100" }) == expected_status);
    EXPECT(nfq_stub.destroy_calls == 1);
    EXPECT(nfq_stub.close_calls == 1);
}

void test_daemon_poll_and_receive_paths()
{
    run_loop_case({ 0, 0, 0, true }, {}, 0, EXIT_SUCCESS);
    run_loop_case({ -1, 0, EINTR, true }, {}, 0, EXIT_SUCCESS);
    run_loop_case({ -1, 0, EIO, true }, {}, 0, EXIT_FAILURE);
    run_loop_case({ 1, POLLERR, 0, true }, {}, 0, EXIT_FAILURE);
    run_loop_case({ 1, 0, 0, true }, {}, 0, EXIT_SUCCESS);
    run_loop_case({ 1, POLLIN, 0, true }, { { 8, 0 } }, 0, EXIT_SUCCESS);
    run_loop_case({ 1, POLLIN, 0, true }, { { 8, 0 } }, -1, EXIT_FAILURE);
    run_loop_case({ 1, POLLIN, 0, true }, { { -1, EINTR } }, 0, EXIT_SUCCESS);
    run_loop_case({ 1, POLLIN, 0, true }, { { -1, ENOBUFS } }, 0, EXIT_SUCCESS);
    run_loop_case({ 1, POLLIN, 0, true }, { { -1, EIO } }, 0, EXIT_FAILURE);
}

} // namespace


int benchmark_packets()
{
    for (unsigned int scenario = 0; scenario < 3U; ++scenario) {
        reset_stubs();
        app_ctx ctx = {};
        if (scenario != 0)
            ctx.dns_servers = { address("fd00::53"), address("fd00::54") };
        if (ctx.dns_servers.empty())
            ctx.dns_cache.refresh();
        nfgenmsg message = bridge_message();
        auto input = scenario == 2U ?
            dhcpv6_packet(Tins::DHCPv6::REPLY,
                { dhcp_option(Tins::DHCPv6::DNS_SERVERS,
                              wire_addresses({ address("fd00::1") })),
                  dhcp_option(100U, std::vector<uint8_t>(2040U, 0x11)) }) :
            router_advertisement(0,
                { rdnss_option({ address(scenario == 0U ? "fd00::53" : "fd00::1") }),
                  ra_option(1U, 255U, 0x11) });
        const auto original = input.bytes;
        prepare_callback_payload(input.bytes);
        const auto process = [&]() {
            std::copy(original.begin(), original.end(), input.bytes.begin());
            nfq_stub.verdicts.clear();
            packet_cb(reinterpret_cast<nfq_q_handle *>(1), &message,
                      reinterpret_cast<nfq_data *>(1), &ctx);
        };
        for (unsigned int i = 0; i < 100U; ++i)
            process();
        const size_t allocations = allocation_count;
        const auto start = std::chrono::steady_clock::now();
        const unsigned int iterations = 20000U;
        for (unsigned int i = 0; i < iterations; ++i)
            process();
        const double elapsed = std::chrono::duration<double, std::micro>(
            std::chrono::steady_clock::now() - start).count();
        std::printf("BENCH %s: %.3f us/packet, %.2f allocations/packet\n",
                    scenario == 0U ? "automatic unchanged RA" :
                    scenario == 1U ? "configured rewrite RA" : "configured rewrite DHCPv6",
                    elapsed / iterations,
                    static_cast<double>(allocation_count - allocations) / iterations);
    }
    return state.failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

int main(int argc, char **argv)
{
    if (argc == 2 && std::strcmp(argv[1], "--benchmark") == 0)
        return benchmark_packets();
    reset_stubs();
    run_test("packet basics", test_packet_basics);
    run_test("DNS cache lifecycle and retries", test_dns_cache);
    run_test("callback cache and buffer reuse", test_callback_cache_and_buffer_reuse);
    run_test("IPv6 packet parsing", test_ipv6_packet_parsing);
    run_test("IPv6 packet replacement", test_ipv6_packet_replacement);
    run_test("logging formatters", test_logging_formatters);
    run_test("address lists and details", test_address_lists_and_details);
    run_test("DUID formatting", test_duid_formatting);
    run_test("checksum equivalence", test_checksum_equivalence);
    run_test("transport parser", test_transport_parser);
    run_test("checksum policy", test_checksum_policy);
    run_test("RA malformed inputs", test_ra_malformed_inputs);
    run_test("RA unchanged and lifetime", test_ra_unchanged_and_lifetime);
    run_test("RA option rewriting", test_ra_option_rewriting);
    run_test("RA SEND and compaction failure", test_ra_send_and_compaction_failure);
    run_test("DHCPv6 option parser", test_dhcp_option_parser);
    run_test("DHCPv6 envelope validation", test_dhcp_envelope_validation);
    run_test("DHCPv6 malformed options", test_dhcp_malformed_options);
    run_test("DHCPv6 unchanged and rewrite", test_dhcp_unchanged_and_rewrite);
    run_test("DHCPv6 authentication and checksum", test_dhcp_authentication_and_checksum);
    run_test("callback envelope policy", test_callback_envelope_policy);
    run_test("callback transport policy", test_callback_transport_policy);
    run_test("callback sanitizer results", test_callback_sanitizer_results);
    run_test("callback configured DNS servers",
             test_callback_configured_dns_servers);
    run_test("verdict memory boundaries", test_verdict_memory_boundaries);
    run_test("callback allocation failures", test_callback_allocation_failures);
    run_test("queue number parsing", test_queue_number_parsing);
    run_test("startup logging", test_startup_logging);
    run_test("signal and CLI paths", test_signal_and_cli_paths);
    run_test("daemon setup failures", test_daemon_setup_failures);
    run_test("daemon poll and receive paths", test_daemon_poll_and_receive_paths);

    std::printf("\n%u tests, %u assertions, %u failures\n",
                state.tests, state.assertions, state.failures);
    return state.failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
