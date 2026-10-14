#ifndef L2DNS6RW_DNS_H
#define L2DNS6RW_DNS_H

#include <net/if.h>
#include <netinet/in.h>
#include <stdbool.h>

#define DNS_SNAPSHOT_MAX 128

/* The first unique local address (fc00::/7) of each interface, by name. */
struct dns_snapshot {
    unsigned int count;
    struct {
        char name[IF_NAMESIZE];
        struct in6_addr address;
    } entries[DNS_SNAPSHOT_MAX];
};

/* Fills snapshot from getifaddrs(); returns -1 with errno set on failure. */
int dns_snapshot_take(struct dns_snapshot *snapshot);

/* Sets master to the name of device's bridge; false when it has none. */
bool dns_bridge_master(const char *device, char *master);

/*
 * The DNS address for device in automatic mode: its own first ULA, else the
 * first ULA of master (its bridge, or "" for none). Sets *source to the name
 * the address came from. False when neither has one.
 */
bool dns_select(
    const struct dns_snapshot *snapshot,
    const char *device,
    const char *master,
    struct in6_addr *address,
    const char **source
);

bool dns_is_ula(const struct in6_addr *address);

#endif
