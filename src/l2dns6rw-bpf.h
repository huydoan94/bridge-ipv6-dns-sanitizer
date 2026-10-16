/* Shared by the BPF program (src/l2dns6rw.bpf.c) and the daemon. */
#ifndef L2DNS6RW_BPF_H
#define L2DNS6RW_BPF_H

#include <linux/types.h>

/* Longest RA or DHCPv6 message the program rewrites; longer ones are dropped. */
#define L2DNS6RW_MAX_MESSAGE 2048
#define L2DNS6RW_MAX_DNS_SERVERS 8
#define L2DNS6RW_MAX_DEVICES 64

/* Value of the dns map, keyed by the ingress device's ifindex. */
struct l2dns6rw_dns {
    __u32 count;
    __u8 servers[L2DNS6RW_MAX_DNS_SERVERS][16];
};

/* Value of the settings map's only entry. */
struct l2dns6rw_settings {
    __u32 verbose; /* nonzero: also report rewritten packets */
};

enum l2dns6rw_counter {
    L2DNS6RW_COUNTER_SEEN,
    L2DNS6RW_COUNTER_CHANGED,
    L2DNS6RW_COUNTER_UNCHANGED,
    L2DNS6RW_COUNTER_DROPPED,
    L2DNS6RW_COUNTER_MAX,
};

enum l2dns6rw_kind {
    L2DNS6RW_KIND_RA,
    L2DNS6RW_KIND_DHCPV6_ADVERTISE,
    L2DNS6RW_KIND_DHCPV6_REPLY,
    L2DNS6RW_KIND_DHCPV6,  /* a DHCPv6 message not yet classified */
    L2DNS6RW_KIND_UNKNOWN, /* past more extension headers than walked */
};

enum l2dns6rw_verdict {
    L2DNS6RW_VERDICT_CHANGED,
    L2DNS6RW_VERDICT_DROPPED,
};

enum l2dns6rw_reason {
    L2DNS6RW_REASON_NONE,
    L2DNS6RW_REASON_FRAGMENT,
    L2DNS6RW_REASON_JUMBOGRAM,
    L2DNS6RW_REASON_TRUNCATED,
    L2DNS6RW_REASON_TOO_LONG,
    L2DNS6RW_REASON_TOO_MANY_OPTIONS,
    L2DNS6RW_REASON_NO_DNS,
    L2DNS6RW_REASON_PROTECTED,
    L2DNS6RW_REASON_WRITE_FAILED,
    L2DNS6RW_REASON_MALFORMED_OPTION,
    L2DNS6RW_REASON_MALFORMED_HEADER,
    L2DNS6RW_REASON_TOO_MANY_HEADERS,
    L2DNS6RW_REASON_ROUTED,
};

/* One ring-buffer report: drops always, rewrites when verbose. */
struct l2dns6rw_event {
    __u32 ifindex;
    __u8 kind;
    __u8 verdict;
    __u8 reason;
    __u8 changed_lifetime; /* RA: the router lifetime was set to 0 */
    __u16 lifetime;        /* RA: the original router lifetime, in seconds */
    __u16 dns_options;     /* RDNSS or DHCPv6 DNS options in the original */
    __u16 dns_addresses;   /* addresses in those options */
    __u16 removed;         /* DNSSL, PvD, Domain List and bad-length DNS options removed */
    __u16 length_before;   /* L4 message length, in bytes */
    __u16 length_after;
    __u8 source[16];
};

#endif
