#include "events.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>

const char *events_reason(unsigned int reason)
{
    switch (reason) {
    case L2DNS6RW_REASON_NONE:
        return "none";
    case L2DNS6RW_REASON_FRAGMENT:
        return "fragmented";
    case L2DNS6RW_REASON_JUMBOGRAM:
        return "IPv6 jumbogram";
    case L2DNS6RW_REASON_TRUNCATED:
        return "truncated";
    case L2DNS6RW_REASON_TOO_LONG:
        return "message or rewrite longer than 2048 bytes";
    case L2DNS6RW_REASON_TOO_MANY_OPTIONS:
        return "more than 64 options";
    case L2DNS6RW_REASON_NO_DNS:
        return "no DNS address for this device";
    case L2DNS6RW_REASON_PROTECTED:
        return "SEND-signed or authenticated message needs a rewrite";
    case L2DNS6RW_REASON_WRITE_FAILED:
        return "could not write the rewritten packet";
    case L2DNS6RW_REASON_MALFORMED_OPTION:
        return "malformed option";
    case L2DNS6RW_REASON_MALFORMED_HEADER:
        return "malformed header";
    case L2DNS6RW_REASON_TOO_MANY_HEADERS:
        return "more than 8 IPv6 extension headers";
    case L2DNS6RW_REASON_ROUTED:
        return "routing header with segments left";
    default:
        return "unknown";
    }
}

static const char *kind_name(unsigned int kind)
{
    switch (kind) {
    case L2DNS6RW_KIND_RA:
        return "RA";
    case L2DNS6RW_KIND_DHCPV6_ADVERTISE:
        return "DHCPv6-Advertise";
    case L2DNS6RW_KIND_DHCPV6_REPLY:
        return "DHCPv6-Reply";
    case L2DNS6RW_KIND_UNKNOWN:
        return "unknown";
    default:
        return "DHCPv6";
    }
}

void events_format(const struct l2dns6rw_event *event, const char *device, char *line, size_t size)
{
    char source[INET6_ADDRSTRLEN];

    if (inet_ntop(AF_INET6, event->source, source, sizeof(source)) == NULL)
        snprintf(source, sizeof(source), "?");
    switch (event->verdict) {
    case L2DNS6RW_VERDICT_CHANGED:
        if (event->kind == L2DNS6RW_KIND_RA) {
            snprintf(
                line,
                size,
                "dev=%s type=RA from=%s rewritten router-lifetime=%u->%u rdnss-options=%u rdnss-addresses=%u "
                "removed=%u bytes=%u->%u",
                device,
                source,
                event->lifetime,
                event->changed_lifetime ? 0U : event->lifetime,
                event->dns_options,
                event->dns_addresses,
                event->removed,
                event->length_before,
                event->length_after
            );
        } else {
            snprintf(
                line,
                size,
                "dev=%s type=%s from=%s rewritten dns-options=%u dns-addresses=%u removed=%u bytes=%u->%u",
                device,
                kind_name(event->kind),
                source,
                event->dns_options,
                event->dns_addresses,
                event->removed,
                event->length_before,
                event->length_after
            );
        }
        break;
    default:
        snprintf(
            line,
            size,
            "dev=%s type=%s from=%s DROP: %s",
            device,
            kind_name(event->kind),
            source,
            events_reason(event->reason)
        );
        break;
    }
}
