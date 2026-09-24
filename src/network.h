#ifndef BRIDGE_IPV6_DNS_SANITIZER_NETWORK_H
#define BRIDGE_IPV6_DNS_SANITIZER_NETWORK_H

#include <stddef.h>
#include <stdint.h>

#include <netinet/in.h>

int resolve_local_dns(
    uint32_t indev,
    uint32_t physindev,
    struct in6_addr *dns,
    char *source_ifname,
    size_t source_ifname_len
);

#endif
