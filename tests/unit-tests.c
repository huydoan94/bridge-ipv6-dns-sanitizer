/*
 * Host unit tests for the daemon's logic: option parsing, automatic DNS
 * selection and log-line formatting. The BPF program is tested in the kernel
 * by tests/bpf (BPF_PROG_TEST_RUN), which needs root.
 */
#include <arpa/inet.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dns.h"
#include "events.h"
#include "options.h"

static unsigned int checks;
static unsigned int failures;

#define EXPECT(condition) expect((condition), #condition, __FILE__, __LINE__)

static void expect(int condition, const char *text, const char *file, int line)
{
    checks++;
    if (!condition) {
        failures++;
        fprintf(stderr, "FAIL %s:%d: %s\n", file, line, text);
    }
}

static struct in6_addr address(const char *text)
{
    struct in6_addr value;

    if (inet_pton(AF_INET6, text, &value) != 1)
        abort();
    return value;
}

static enum options_result parse(struct options *options, char *error, const char *first, ...)
{
    char *argv[40];
    int argc = 0;
    va_list arguments;

    argv[argc++] = (char *)"l2dns6rw";
    va_start(arguments, first);
    for (const char *argument = first; argument != NULL; argument = va_arg(arguments, const char *))
        argv[argc++] = (char *)argument;
    va_end(arguments);
    argv[argc] = NULL;
    return options_parse(options, argc, argv, error, 128);
}

/* Parses -i l2vl0 plus count "-d fd00::N" (flag "-d") or count "-i dN" (flag "-i"). */
static enum options_result parse_repeated(struct options *options, char *error, const char *flag, unsigned int count)
{
    static char values[OPTIONS_MAX_DEVICES + 2][16];
    char *argv[2 * (OPTIONS_MAX_DEVICES + 2) + 4];
    int argc = 0;

    argv[argc++] = (char *)"l2dns6rw";
    if (strcmp(flag, "-d") == 0) {
        argv[argc++] = (char *)"-i";
        argv[argc++] = (char *)"l2vl0";
    }
    for (unsigned int i = 0; i < count; i++) {
        snprintf(values[i], sizeof(values[i]), strcmp(flag, "-d") == 0 ? "fd00::%u" : "d%u", i + 1);
        argv[argc++] = (char *)flag;
        argv[argc++] = values[i];
    }
    argv[argc] = NULL;
    return options_parse(options, argc, argv, error, 128);
}

static void test_options(void)
{
    struct options options;
    char error[128];
    const struct in6_addr primary = address("fd00::53");

    EXPECT(
        parse(&options, error, "-i", "l2vl0", "-i", "vxlan2", "-d", "fd00::53", "-d", "2001:db8::53", "-v", NULL) ==
        OPTIONS_RUN
    );
    EXPECT(options.device_count == 2 && strcmp(options.devices[1], "vxlan2") == 0);
    EXPECT(options.dns_count == 2 && memcmp(&options.dns[0], &primary, sizeof(primary)) == 0);
    EXPECT(options.verbose && !options.detach);
    EXPECT(strcmp(options.object_path, DEFAULT_OBJECT_PATH) == 0);
    EXPECT(strcmp(options.pin_path, DEFAULT_PIN_PATH) == 0);

    EXPECT(parse(&options, error, "-i", "l2vl0", "-o", "/tmp/x.o", "-p", "/sys/fs/bpf/t", NULL) == OPTIONS_RUN);
    EXPECT(options.dns_count == 0 && !options.verbose);
    EXPECT(strcmp(options.object_path, "/tmp/x.o") == 0 && strcmp(options.pin_path, "/sys/fs/bpf/t") == 0);

    EXPECT(parse(&options, error, "-D", NULL) == OPTIONS_RUN && options.detach);
    EXPECT(parse(&options, error, "-h", NULL) == OPTIONS_HELP);

    EXPECT(parse(&options, error, NULL) == OPTIONS_INVALID);
    EXPECT(strstr(error, "at least one device") != NULL);
    EXPECT(parse(&options, error, "-v", NULL) == OPTIONS_INVALID);
    EXPECT(parse(&options, error, "-i", "l2vl0", "extra", NULL) == OPTIONS_INVALID);
    EXPECT(strstr(error, "unexpected argument 'extra'") != NULL);
    EXPECT(parse(&options, error, "-i", "", NULL) == OPTIONS_INVALID);
    EXPECT(parse(&options, error, "-i", "a/b", NULL) == OPTIONS_INVALID);
    EXPECT(parse(&options, error, "-i", "sixteen-chars-xx", NULL) == OPTIONS_INVALID);
    EXPECT(parse(&options, error, "-i", "fifteen-chars-x", NULL) == OPTIONS_RUN);
    EXPECT(parse(&options, error, "-i", "l2vl0", "-d", "192.0.2.53", NULL) == OPTIONS_INVALID);
    EXPECT(strstr(error, "invalid IPv6 DNS server '192.0.2.53'") != NULL);
    EXPECT(parse(&options, error, "-i", "l2vl0", "-x", NULL) == OPTIONS_INVALID);
    EXPECT(strcmp(error, "unknown option or missing value: -x") == 0);
    EXPECT(parse(&options, error, "-i", NULL) == OPTIONS_INVALID);
    EXPECT(strcmp(error, "unknown option or missing value: -i") == 0);

    EXPECT(parse_repeated(&options, error, "-d", L2DNS6RW_MAX_DNS_SERVERS) == OPTIONS_RUN);
    EXPECT(options.dns_count == L2DNS6RW_MAX_DNS_SERVERS);
    EXPECT(parse_repeated(&options, error, "-d", L2DNS6RW_MAX_DNS_SERVERS + 1) == OPTIONS_INVALID);
    EXPECT(strstr(error, "too many DNS servers") != NULL);

    EXPECT(parse_repeated(&options, error, "-i", OPTIONS_MAX_DEVICES) == OPTIONS_RUN);
    EXPECT(options.device_count == OPTIONS_MAX_DEVICES);
    EXPECT(parse_repeated(&options, error, "-i", OPTIONS_MAX_DEVICES + 1) == OPTIONS_INVALID);
    EXPECT(strstr(error, "too many devices") != NULL);
}

static void snapshot_add(struct dns_snapshot *snapshot, const char *name, const char *text)
{
    snprintf(snapshot->entries[snapshot->count].name, IF_NAMESIZE, "%s", name);
    snapshot->entries[snapshot->count].address = address(text);
    snapshot->count++;
}

static void test_dns_selection(void)
{
    struct dns_snapshot snapshot = {0};
    struct in6_addr selected;
    const struct in6_addr bridge = address("fd00:abcd::1");
    const struct in6_addr port = address("fc00::7");
    const char *source;

    EXPECT(dns_is_ula(&bridge) && dns_is_ula(&port));
    selected = address("fdff:ffff::1");
    EXPECT(dns_is_ula(&selected));
    selected = address("fe80::1");
    EXPECT(!dns_is_ula(&selected));
    selected = address("fbff::1");
    EXPECT(!dns_is_ula(&selected));
    selected = address("2001:db8::1");
    EXPECT(!dns_is_ula(&selected));

    EXPECT(!dns_select(&snapshot, "l2vl0", "br-lan", &selected, &source));

    snapshot_add(&snapshot, "br-lan", "fd00:abcd::1");
    EXPECT(dns_select(&snapshot, "l2vl0", "br-lan", &selected, &source));
    EXPECT(memcmp(&selected, &bridge, sizeof(bridge)) == 0 && strcmp(source, "br-lan") == 0);
    EXPECT(!dns_select(&snapshot, "l2vl0", "", &selected, &source));
    EXPECT(!dns_select(&snapshot, "l2vl0", "br-guest", &selected, &source));

    /* The device's own ULA wins over its bridge's. */
    snapshot_add(&snapshot, "l2vl0", "fc00::7");
    EXPECT(dns_select(&snapshot, "l2vl0", "br-lan", &selected, &source));
    EXPECT(memcmp(&selected, &port, sizeof(port)) == 0 && strcmp(source, "l2vl0") == 0);
}

static struct l2dns6rw_event event(unsigned int kind, unsigned int verdict, unsigned int reason)
{
    struct l2dns6rw_event value;
    const struct in6_addr source = address("fe80::a");

    memset(&value, 0, sizeof(value));
    value.ifindex = 7;
    value.kind = (__u8)kind;
    value.verdict = (__u8)verdict;
    value.reason = (__u8)reason;
    memcpy(value.source, &source, sizeof(value.source));
    return value;
}

static void test_event_lines(void)
{
    struct l2dns6rw_event value;
    char line[256];

    value = event(L2DNS6RW_KIND_RA, L2DNS6RW_VERDICT_CHANGED, L2DNS6RW_REASON_NONE);
    value.changed_lifetime = 1;
    value.lifetime = 1800;
    value.dns_options = 2;
    value.dns_addresses = 3;
    value.removed = 1;
    value.length_before = 104;
    value.length_after = 48;
    events_format(&value, "l2vl0", line, sizeof(line));
    EXPECT(strcmp(line, "dev=l2vl0 type=RA from=fe80::a rewritten router-lifetime=1800->0 rdnss-options=2 "
                        "rdnss-addresses=3 removed=1 bytes=104->48") == 0);

    value.changed_lifetime = 0;
    value.lifetime = 0;
    events_format(&value, "l2vl0", line, sizeof(line));
    EXPECT(strstr(line, "router-lifetime=0->0") != NULL);

    value = event(L2DNS6RW_KIND_DHCPV6_REPLY, L2DNS6RW_VERDICT_CHANGED, L2DNS6RW_REASON_NONE);
    value.dns_options = 1;
    value.dns_addresses = 1;
    value.removed = 1;
    value.length_before = 63;
    value.length_after = 46;
    events_format(&value, "l2vl0", line, sizeof(line));
    EXPECT(strcmp(line, "dev=l2vl0 type=DHCPv6-Reply from=fe80::a rewritten dns-options=1 dns-addresses=1 "
                        "removed=1 bytes=63->46") == 0);

    value = event(L2DNS6RW_KIND_DHCPV6_ADVERTISE, L2DNS6RW_VERDICT_DROPPED, L2DNS6RW_REASON_PROTECTED);
    events_format(&value, "l2vl0", line, sizeof(line));
    EXPECT(strcmp(line, "dev=l2vl0 type=DHCPv6-Advertise from=fe80::a DROP: SEND-signed or authenticated message "
                        "needs a rewrite") == 0);

    value = event(L2DNS6RW_KIND_UNKNOWN, L2DNS6RW_VERDICT_DROPPED, L2DNS6RW_REASON_TOO_MANY_HEADERS);
    events_format(&value, "eth9", line, sizeof(line));
    EXPECT(strcmp(line, "dev=eth9 type=unknown from=fe80::a DROP: more than 8 IPv6 extension headers") == 0);

    value = event(L2DNS6RW_KIND_RA, L2DNS6RW_VERDICT_DROPPED, L2DNS6RW_REASON_MALFORMED_OPTION);
    events_format(&value, "l2vl0", line, sizeof(line));
    EXPECT(strcmp(line, "dev=l2vl0 type=RA from=fe80::a DROP: malformed option") == 0);

    value = event(L2DNS6RW_KIND_DHCPV6_REPLY, L2DNS6RW_VERDICT_DROPPED, L2DNS6RW_REASON_ROUTED);
    events_format(&value, "l2vl0", line, sizeof(line));
    EXPECT(strcmp(line, "dev=l2vl0 type=DHCPv6-Reply from=fe80::a DROP: routing header with segments left") == 0);

    /* Every reason the program reports has its own text. */
    for (unsigned int reason = L2DNS6RW_REASON_NONE; reason <= L2DNS6RW_REASON_ROUTED; reason++)
        EXPECT(strcmp(events_reason(reason), "unknown") != 0);
    EXPECT(strcmp(events_reason(L2DNS6RW_REASON_ROUTED + 1), "unknown") == 0);

    /* A long device name cannot overflow the line. */
    events_format(&value, "a-very-long-dev", line, 16);
    EXPECT(strlen(line) == 15);
}

int main(void)
{
    test_options();
    test_dns_selection();
    test_event_lines();
    printf("%u checks, %u failures\n", checks, failures);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
