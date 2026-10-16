// SPDX-License-Identifier: MIT
/*
 * l2dns6rw: sanitizes IPv6 DNS settings in Router Advertisements and DHCPv6
 * replies at tcx ingress of the devices the daemon attaches it to (for
 * example a VXLAN port), before the bridge forwards them.
 *
 * RA: router lifetime -> 0; the first RDNSS option carries the device's DNS
 * list; later RDNSS, DNSSL and PvD options are removed. DHCPv6 Advertise and
 * Reply: the first DNS Servers option carries the list; later ones and Domain
 * List options are removed. The daemon fills the dns map per ingress ifindex,
 * from configured servers or the device's own ULA.
 *
 * Every rewrite takes one path. The L4 message is copied into a per-CPU input
 * buffer (which also gives its checksum state), rebuilt option by option into
 * an output buffer by walk_option(), and written back after the packet tail is
 * resized. walk_option() is a global function: the verifier checks it once for
 * any state, and the buffer masks alone keep it in bounds. It takes no packet
 * argument because OpenWrt kernels carry no vmlinux BTF, which the verifier
 * needs to pass the packet context to a global function. A message that
 * arrived with a bad checksum leaves with a bad one.
 *
 * Dropped: more extension headers than the program walks (they could hide a
 * target), a first fragment of a target, a jumbogram, a truncated target, no
 * DNS list for the device, a SEND-signed RA or authenticated DHCPv6 message
 * that needs a rewrite, and anything beyond this program's limits (a message
 * over L2DNS6RW_MAX_MESSAGE bytes or with more than MAX_OPTIONS options).
 * Malformed options pass unchanged. Everything else passes untouched.
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "l2dns6rw-bpf.h"

#define MAX_L4 L2DNS6RW_MAX_MESSAGE
#define IPV6_OFFSET 14 /* after the Ethernet header */
#define L3_PAYLOAD_OFFSET (IPV6_OFFSET + 40)

/* Offsets are masked below MAX_L4; with lengths up to MAX_L4 they stay inside. */
#define BUFFER_MASK (MAX_L4 - 1)
#define BUFFER_SIZE (2 * MAX_L4)
#define CSUM_CHUNK 512
#define MAX_OPTIONS 64
#define MAX_EXTENSION_HEADERS 8
#define EVENT_BUFFER_BYTES (64 * 1024)

#define NEXTHDR_HOP 0
#define NEXTHDR_UDP 17
#define NEXTHDR_ROUTING 43
#define NEXTHDR_FRAGMENT 44
#define NEXTHDR_ESP 50
#define NEXTHDR_AUTH 51
#define NEXTHDR_ICMPV6 58
#define NEXTHDR_DEST 60
#define NEXTHDR_MOBILITY 135

#define ICMPV6_ROUTER_ADVERT 134
#define RA_HEADER_LEN 16
#define RA_LIFETIME_OFFSET 6
#define ND_OPT_RSA_SIGNATURE 12
#define ND_OPT_PVD 21
#define ND_OPT_RDNSS 25
#define ND_OPT_DNSSL 31
#define RDNSS_FIXED_LEN 8

#define DHCPV6_SERVER_PORT 547
#define DHCPV6_CLIENT_PORT 546
#define DHCPV6_ADVERTISE 2
#define DHCPV6_REPLY 7
#define DHCPV6_HEADER_LEN 12 /* UDP header and message type + transaction ID */
#define DHCPV6_OPTION_HEADER_LEN 4
#define DHCPV6_OPT_AUTH 11
#define DHCPV6_OPT_DNS_SERVERS 23
#define DHCPV6_OPT_DOMAIN_LIST 24

struct scratch {
    __u8 input[BUFFER_SIZE];
    __u8 output[BUFFER_SIZE];
};

/* Pinned by name under the daemon's pin path, so a restarted daemon reuses them. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, L2DNS6RW_MAX_DEVICES);
    __type(key, __u32);
    __type(value, struct l2dns6rw_dns);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} dns SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct l2dns6rw_settings);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} settings SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, L2DNS6RW_COUNTER_MAX);
    __type(key, __u32);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} counters SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, EVENT_BUFFER_BYTES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct scratch);
} scratch SEC(".maps");

/* One walk over a message's options, kept in the caller's stack. */
struct walk_state {
    __u32 ifindex;
    __u32 len;      /* message length in the input buffer */
    __u32 position; /* next option in the input buffer */
    __u32 out;      /* bytes written to the output buffer */
    __u32 is_ra;
    __u32 dns_options;
    __u32 dns_addresses;
    __u32 removed; /* DNSSL, PvD, Domain List and bad-length DNS options dropped */
    __u32 changed;
    __u32 protected; /* SEND signature or DHCPv6 Authentication present */
    __u32 malformed;
    __u32 over_limit;
    __u32 no_dns;
    __u32 done;
};

#define WALK_NEXT 0
#define WALK_STOP 1

static __always_inline void count(__u32 counter)
{
    __u64 *value = bpf_map_lookup_elem(&counters, &counter);

    if (value)
        *value += 1;
}

/* Counts a verdict on a target packet, reports it, and returns the tcx action. */
static __always_inline int finish(
    const struct walk_state *state,
    const struct ipv6hdr *ip6,
    __u8 kind,
    __u16 lifetime,
    __u8 verdict,
    __u8 reason
)
{
    const __u32 key = 0;
    struct l2dns6rw_settings *current = bpf_map_lookup_elem(&settings, &key);
    struct l2dns6rw_event *event;

    count(verdict == L2DNS6RW_VERDICT_CHANGED ? L2DNS6RW_COUNTER_CHANGED : L2DNS6RW_COUNTER_DROPPED);
    if (verdict != L2DNS6RW_VERDICT_CHANGED || (current && current->verbose)) {
        event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
        if (event) {
            event->ifindex = state->ifindex;
            event->kind = kind;
            event->verdict = verdict;
            event->reason = reason;
            event->changed_lifetime = state->is_ra && lifetime != 0 && verdict == L2DNS6RW_VERDICT_CHANGED;
            event->lifetime = lifetime;
            event->dns_options = (__u16)state->dns_options;
            event->dns_addresses = (__u16)state->dns_addresses;
            event->removed = (__u16)state->removed;
            event->length_before = (__u16)state->len;
            event->length_after = verdict == L2DNS6RW_VERDICT_CHANGED ? (__u16)state->out : 0;
            __builtin_memcpy(event->source, &ip6->saddr, sizeof(event->source));
            bpf_ringbuf_submit(event, 0);
        }
    }
    return verdict == L2DNS6RW_VERDICT_CHANGED ? TCX_PASS : TCX_DROP;
}

static __always_inline __u32 fold(__u64 sum)
{
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    return (__u32)sum;
}

/* Ones' complement sum of the IPv6 pseudo-header and len bytes of buffer. */
static __always_inline __u64 l4_sum(const struct ipv6hdr *ip6, __u8 protocol, __u8 *buffer, __u32 len)
{
    struct {
        struct in6_addr source;
        struct in6_addr destination;
        __be32 length;
        __u8 zero[3];
        __u8 protocol;
    } pseudo = {};
    __s64 sum;

    pseudo.source = ip6->saddr;
    pseudo.destination = ip6->daddr;
    pseudo.length = bpf_htonl(len);
    pseudo.protocol = protocol;
    sum = bpf_csum_diff(0, 0, (__be32 *)&pseudo, sizeof(pseudo), 0);
    /* The helper sums whole 32-bit words; the caller zeroed the pad bytes. */
    for (__u32 start = 0; start < MAX_L4; start += CSUM_CHUNK) {
        __u32 chunk;

        if (start >= len)
            break;
        chunk = len - start;
        if (chunk > CSUM_CHUNK)
            chunk = CSUM_CHUNK;
        /* Round up to whole words; (512 + 3) & 0x3fc is still 512. */
        chunk = (chunk + 3) & 0x3fc;
        barrier_var(chunk);
        sum = bpf_csum_diff(0, 0, (__be32 *)(buffer + start), chunk, (__wsum)sum);
    }
    return (__u64)(__u32)sum;
}

static __always_inline void copy_bytes(__u8 *to, __u32 to_offset, const __u8 *from, __u32 from_offset, __u32 len)
{
    for (__u32 i = 0; i < MAX_L4; i++) {
        if (i >= len)
            break;
        to[(to_offset + i) & BUFFER_MASK] = from[(from_offset + i) & BUFFER_MASK];
    }
}

/* Writes the device's DNS servers at output offset out; returns their bytes. */
static __always_inline __u32 write_servers(__u8 *output, __u32 out, const struct l2dns6rw_dns *list)
{
    for (__u32 i = 0; i < L2DNS6RW_MAX_DNS_SERVERS * 16; i++) {
        if (i >= list->count * 16)
            break;
        output[(out + i) & BUFFER_MASK] = list->servers[i / 16][i % 16];
    }
    return list->count * 16;
}

/* Nonzero when address_bytes at input offset differ from the device's list. */
static __always_inline int servers_differ(
    const __u8 *input,
    __u32 offset,
    __u32 address_bytes,
    const struct l2dns6rw_dns *list
)
{
    __u8 difference = 0;

    if (address_bytes != list->count * 16)
        return 1;
    for (__u32 i = 0; i < L2DNS6RW_MAX_DNS_SERVERS * 16; i++) {
        if (i >= address_bytes)
            break;
        difference |= input[(offset + i) & BUFFER_MASK] ^ list->servers[i / 16][i % 16];
    }
    return difference != 0;
}

/*
 * Handles the option at state->position of the input buffer: copies,
 * replaces or skips it into the output buffer.
 */
__noinline int walk_option(struct walk_state *state)
{
    const struct l2dns6rw_dns *list;
    struct scratch *work;
    __u32 key = 0, position, option_len, dns_bytes, out;
    const __u8 *input;
    __u8 *output;

    if (!state)
        return WALK_STOP;
    list = bpf_map_lookup_elem(&dns, &state->ifindex);
    work = bpf_map_lookup_elem(&scratch, &key);
    if (!list || list->count == 0 || list->count > L2DNS6RW_MAX_DNS_SERVERS) {
        state->no_dns = 1;
        return WALK_STOP;
    }
    if (!work)
        goto over_limit;
    input = work->input;
    output = work->output;
    dns_bytes = list->count * 16;
    position = state->position;
    out = state->out;
    if (position >= state->len) {
        state->done = 1;
        return WALK_STOP;
    }
    if (state->len > MAX_L4 || out > MAX_L4)
        goto over_limit;

    if (state->is_ra) {
        if (state->len - position < 2)
            goto malformed;
        option_len = input[(position + 1) & BUFFER_MASK] * 8;
        if (option_len == 0 || option_len > state->len - position)
            goto malformed;
        switch (input[position & BUFFER_MASK]) {
        case ND_OPT_PVD:
        case ND_OPT_DNSSL:
            state->changed = 1;
            state->removed++;
            goto next;
        case ND_OPT_RDNSS: {
            __u32 address_bytes = option_len - RDNSS_FIXED_LEN;

            /* Clients ignore an RDNSS of a bad length but keep the rest: remove it. */
            if (address_bytes == 0 || address_bytes % 16 != 0) {
                state->changed = 1;
                state->removed++;
                goto next;
            }
            state->dns_addresses += address_bytes / 16;
            if (++state->dns_options > 1) {
                state->changed = 1;
                goto next;
            }
            if (servers_differ(input, position + RDNSS_FIXED_LEN, address_bytes, list))
                state->changed = 1;
            if (out + RDNSS_FIXED_LEN + dns_bytes > MAX_L4)
                goto over_limit;
            copy_bytes(output, out, input, position, RDNSS_FIXED_LEN);
            output[(out + 1) & BUFFER_MASK] = (__u8)((RDNSS_FIXED_LEN + dns_bytes) / 8);
            out += RDNSS_FIXED_LEN;
            out += write_servers(output, out, list);
            goto next;
        }
        case ND_OPT_RSA_SIGNATURE:
            state->protected = 1;
            break;
        }
    } else {
        __u16 code;

        if (state->len - position < DHCPV6_OPTION_HEADER_LEN)
            goto malformed;
        code = input[position & BUFFER_MASK] << 8 | input[(position + 1) & BUFFER_MASK];
        option_len = DHCPV6_OPTION_HEADER_LEN +
            (input[(position + 2) & BUFFER_MASK] << 8 | input[(position + 3) & BUFFER_MASK]);
        if (option_len > state->len - position)
            goto malformed;
        switch (code) {
        case DHCPV6_OPT_DOMAIN_LIST:
            state->changed = 1;
            state->removed++;
            goto next;
        case DHCPV6_OPT_DNS_SERVERS: {
            __u32 address_bytes = option_len - DHCPV6_OPTION_HEADER_LEN;

            /* Clients ignore a DNS option of a bad length but keep the rest: remove it. */
            if (address_bytes == 0 || address_bytes % 16 != 0) {
                state->changed = 1;
                state->removed++;
                goto next;
            }
            state->dns_addresses += address_bytes / 16;
            if (++state->dns_options > 1) {
                state->changed = 1;
                goto next;
            }
            if (servers_differ(input, position + DHCPV6_OPTION_HEADER_LEN, address_bytes, list))
                state->changed = 1;
            if (out + DHCPV6_OPTION_HEADER_LEN + dns_bytes > MAX_L4)
                goto over_limit;
            output[out & BUFFER_MASK] = 0;
            output[(out + 1) & BUFFER_MASK] = DHCPV6_OPT_DNS_SERVERS;
            output[(out + 2) & BUFFER_MASK] = (__u8)(dns_bytes >> 8);
            output[(out + 3) & BUFFER_MASK] = (__u8)dns_bytes;
            out += DHCPV6_OPTION_HEADER_LEN;
            out += write_servers(output, out, list);
            goto next;
        }
        case DHCPV6_OPT_AUTH:
            state->protected = 1;
            break;
        }
    }

    /* Any other option is copied unchanged. */
    if (out + option_len > MAX_L4)
        goto over_limit;
    copy_bytes(output, out, input, position, option_len);
    out += option_len;
next:
    state->position = position + option_len;
    state->out = out;
    return WALK_NEXT;
malformed:
    state->malformed = 1;
    return WALK_STOP;
over_limit:
    state->over_limit = 1;
    return WALK_STOP;
}

#define L4_PASS -1
#define L4_UNRESOLVED -2 /* more extension headers than walked: could hide a target */

/* What the extension headers before the L4 header said. */
struct headers {
    int first_fragment; /* a fragment with more to follow: the message is incomplete */
    int routed;         /* a routing header with segments left: not for this hop */
    int authenticated;  /* an AH header: a rewrite would break it */
};

/*
 * Walks extension headers; returns the L4 protocol and sets *offset, or
 * L4_PASS (no L4 header to see: a later fragment, ESP) or L4_UNRESOLVED.
 */
static __always_inline int find_l4(struct __sk_buff *skb, __u8 next_header, __u32 *offset, struct headers *headers)
{
    for (int i = 0; i < MAX_EXTENSION_HEADERS; i++) {
        __u8 header[8];

        switch (next_header) {
        case NEXTHDR_HOP:
        case NEXTHDR_DEST:
            if (bpf_skb_load_bytes(skb, *offset, header, 2) < 0)
                return L4_PASS;
            next_header = header[0];
            *offset += (header[1] + 1) * 8;
            break;
        case NEXTHDR_ROUTING:
            if (bpf_skb_load_bytes(skb, *offset, header, 4) < 0)
                return L4_PASS;
            if (header[3] != 0)
                headers->routed = 1;
            next_header = header[0];
            *offset += (header[1] + 1) * 8;
            break;
        case NEXTHDR_AUTH:
            if (bpf_skb_load_bytes(skb, *offset, header, 2) < 0)
                return L4_PASS;
            headers->authenticated = 1;
            next_header = header[0];
            *offset += (header[1] + 2) * 4;
            break;
        case NEXTHDR_FRAGMENT: {
            __u16 fragment;

            if (bpf_skb_load_bytes(skb, *offset, header, 8) < 0)
                return L4_PASS;
            fragment = header[2] << 8 | header[3];
            /* A later fragment has no L4 header; an atomic one is walked through. */
            if ((fragment & ~7U) != 0)
                return L4_PASS;
            if (fragment & 1)
                headers->first_fragment = 1;
            next_header = header[0];
            *offset += 8;
            break;
        }
        case NEXTHDR_ESP: /* encrypted: nothing to inspect */
            return L4_PASS;
        default:
            return next_header;
        }
    }
    return L4_UNRESOLVED;
}

SEC("tcx/ingress")
int l2dns6rw_ingress(struct __sk_buff *skb)
{
    struct walk_state state = {};
    struct ipv6hdr ip6;
    __u32 l4_offset = L3_PAYLOAD_OFFSET, l3_end, len, header_len, key = 0;
    __u64 size;
    struct headers headers = {};
    int protocol, checksum_valid;
    __u8 kind = L2DNS6RW_KIND_RA;
    __u16 lifetime = 0;
    struct scratch *work;
    __u8 *input, *output;
    __u16 checksum;

    if (skb->protocol != bpf_htons(ETH_P_IPV6))
        return TCX_PASS;
    if (bpf_skb_load_bytes(skb, IPV6_OFFSET, &ip6, sizeof(ip6)) < 0 || ip6.version != 6)
        return TCX_PASS;
    protocol = find_l4(skb, ip6.nexthdr, &l4_offset, &headers);
    if (protocol == L4_UNRESOLVED) {
        /* Stacked extension headers must not carry an RA or DHCPv6 reply past the program. */
        count(L2DNS6RW_COUNTER_SEEN);
        state.ifindex = skb->ifindex;
        return finish(
            &state,
            &ip6,
            L2DNS6RW_KIND_UNKNOWN,
            0,
            L2DNS6RW_VERDICT_DROPPED,
            L2DNS6RW_REASON_TOO_MANY_HEADERS
        );
    }
    if (protocol == NEXTHDR_ICMPV6) {
        __u8 type;

        if (bpf_skb_load_bytes(skb, l4_offset, &type, 1) < 0 || type != ICMPV6_ROUTER_ADVERT)
            return TCX_PASS;
        state.is_ra = 1;
        header_len = RA_HEADER_LEN;
    } else if (protocol == NEXTHDR_UDP) {
        __be16 ports[2];

        if (bpf_skb_load_bytes(skb, l4_offset, ports, sizeof(ports)) < 0 ||
            ports[0] != bpf_htons(DHCPV6_SERVER_PORT) || ports[1] != bpf_htons(DHCPV6_CLIENT_PORT))
            return TCX_PASS;
        kind = L2DNS6RW_KIND_DHCPV6;
        header_len = DHCPV6_HEADER_LEN;
    } else {
        return TCX_PASS;
    }

    count(L2DNS6RW_COUNTER_SEEN);
    state.ifindex = skb->ifindex;
    if (headers.first_fragment)
        return finish(&state, &ip6, kind, 0, L2DNS6RW_VERDICT_DROPPED, L2DNS6RW_REASON_FRAGMENT);
    if (headers.routed)
        return finish(&state, &ip6, kind, 0, L2DNS6RW_VERDICT_DROPPED, L2DNS6RW_REASON_ROUTED);
    state.protected = headers.authenticated;
    if (ip6.payload_len == 0)
        return finish(&state, &ip6, kind, 0, L2DNS6RW_VERDICT_DROPPED, L2DNS6RW_REASON_JUMBOGRAM);
    l3_end = L3_PAYLOAD_OFFSET + bpf_ntohs(ip6.payload_len);
    if (l3_end > skb->len || l3_end <= l4_offset)
        return finish(&state, &ip6, kind, 0, L2DNS6RW_VERDICT_DROPPED, L2DNS6RW_REASON_TRUNCATED);
    len = l3_end - l4_offset;
    if (!state.is_ra) {
        __be16 udp_length;

        /* Too short for a DHCPv6 message: clients discard it, so it goes no further. */
        if (len < DHCPV6_HEADER_LEN ||
            bpf_skb_load_bytes(skb, l4_offset + 4, &udp_length, sizeof(udp_length)) < 0 ||
            bpf_ntohs(udp_length) < DHCPV6_HEADER_LEN)
            return finish(&state, &ip6, kind, 0, L2DNS6RW_VERDICT_DROPPED, L2DNS6RW_REASON_MALFORMED_HEADER);
        if (bpf_ntohs(udp_length) > len)
            return finish(&state, &ip6, kind, 0, L2DNS6RW_VERDICT_DROPPED, L2DNS6RW_REASON_TRUNCATED);
        len = bpf_ntohs(udp_length);
    } else if (len < RA_HEADER_LEN) {
        return finish(&state, &ip6, kind, 0, L2DNS6RW_VERDICT_DROPPED, L2DNS6RW_REASON_MALFORMED_HEADER);
    }
    state.len = len;

    work = bpf_map_lookup_elem(&scratch, &key);
    if (!work)
        return finish(&state, &ip6, kind, 0, L2DNS6RW_VERDICT_DROPPED, L2DNS6RW_REASON_WRITE_FAILED);
    input = work->input;
    output = work->output;
    /*
     * The check and the helper's size use one 64-bit copy the compiler cannot
     * see through. On the 32-bit len, clang 18 checks a zero-extended copy
     * and passes the original register, which the verifier then still sees
     * as unbounded.
     */
    size = len;
    barrier_var(size);
    if (size == 0 || size > MAX_L4)
        return finish(&state, &ip6, kind, 0, L2DNS6RW_VERDICT_DROPPED, L2DNS6RW_REASON_TOO_LONG);
    if (bpf_skb_load_bytes(skb, l4_offset, input, size) < 0)
        return finish(&state, &ip6, kind, 0, L2DNS6RW_VERDICT_DROPPED, L2DNS6RW_REASON_TRUNCATED);
    __builtin_memset(input + (len & BUFFER_MASK), 0, 4);
    checksum_valid = fold(l4_sum(&ip6, (__u8)protocol, input, len)) == 0xffff;

    if (state.is_ra) {
        lifetime = input[RA_LIFETIME_OFFSET] << 8 | input[RA_LIFETIME_OFFSET + 1];
        if (lifetime != 0)
            state.changed = 1;
    } else {
        if (input[8] == DHCPV6_ADVERTISE) {
            kind = L2DNS6RW_KIND_DHCPV6_ADVERTISE;
        } else if (input[8] == DHCPV6_REPLY) {
            kind = L2DNS6RW_KIND_DHCPV6_REPLY;
        } else {
            count(L2DNS6RW_COUNTER_UNCHANGED);
            return TCX_PASS;
        }
        /* RFC 8200 8.1: a zero UDP checksum is invalid over IPv6. */
        if (input[6] == 0 && input[7] == 0)
            checksum_valid = 0;
    }
    /* The longer fixed header; a DHCPv6 message's extra bytes are rewritten anyway. */
    __builtin_memcpy(output, input, RA_HEADER_LEN);
    state.position = header_len;
    state.out = header_len;
    for (__u32 i = 0; i < MAX_OPTIONS; i++) {
        if (walk_option(&state) == WALK_STOP)
            break;
    }

    if (state.no_dns)
        return finish(&state, &ip6, kind, lifetime, L2DNS6RW_VERDICT_DROPPED, L2DNS6RW_REASON_NO_DNS);
    if (state.malformed)
        return finish(&state, &ip6, kind, lifetime, L2DNS6RW_VERDICT_DROPPED, L2DNS6RW_REASON_MALFORMED_OPTION);
    if (state.over_limit)
        return finish(&state, &ip6, kind, lifetime, L2DNS6RW_VERDICT_DROPPED, L2DNS6RW_REASON_TOO_LONG);
    if (!state.done)
        return finish(&state, &ip6, kind, lifetime, L2DNS6RW_VERDICT_DROPPED, L2DNS6RW_REASON_TOO_MANY_OPTIONS);
    if (!state.changed) {
        count(L2DNS6RW_COUNTER_UNCHANGED);
        return TCX_PASS;
    }
    if (state.protected)
        return finish(&state, &ip6, kind, lifetime, L2DNS6RW_VERDICT_DROPPED, L2DNS6RW_REASON_PROTECTED);

    /* As for the input: len is taken from the checked copy. */
    size = state.out;
    barrier_var(size);
    if (size == 0 || size > MAX_L4)
        return finish(&state, &ip6, kind, lifetime, L2DNS6RW_VERDICT_DROPPED, L2DNS6RW_REASON_TOO_LONG);
    len = (__u32)size;
    if (state.is_ra) {
        output[RA_LIFETIME_OFFSET] = 0;
        output[RA_LIFETIME_OFFSET + 1] = 0;
        output[2] = 0;
        output[3] = 0;
    } else {
        output[4] = (__u8)(len >> 8);
        output[5] = (__u8)len;
        output[6] = 0;
        output[7] = 0;
    }
    __builtin_memset(output + (len & BUFFER_MASK), 0, 4);
    checksum = (__u16)~fold(l4_sum(&ip6, (__u8)protocol, output, len));
    if (!state.is_ra && checksum == 0)
        checksum = 0xffff;
    /* The sum is in wire byte order; flip the lowest bit of the wire value. */
    if (!checksum_valid)
        checksum ^= bpf_htons(1);
    __builtin_memcpy(output + (state.is_ra ? 2 : 6), &checksum, sizeof(checksum));

    {
        __be16 payload_len = bpf_htons((__u16)(l4_offset - L3_PAYLOAD_OFFSET + len));

        if (bpf_skb_change_tail(skb, l4_offset + len, 0) < 0 ||
            bpf_skb_store_bytes(skb, l4_offset, output, len, BPF_F_RECOMPUTE_CSUM) < 0 ||
            bpf_skb_store_bytes(skb, IPV6_OFFSET + 4, &payload_len, sizeof(payload_len), BPF_F_RECOMPUTE_CSUM) < 0)
            return finish(&state, &ip6, kind, lifetime, L2DNS6RW_VERDICT_DROPPED, L2DNS6RW_REASON_WRITE_FAILED);
    }
    return finish(&state, &ip6, kind, lifetime, L2DNS6RW_VERDICT_CHANGED, L2DNS6RW_REASON_NONE);
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
