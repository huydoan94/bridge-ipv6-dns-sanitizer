#include "dns.h"

#include <ifaddrs.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define SYSFS_NETWORK_DIRECTORY "/sys/class/net/"

bool dns_is_ula(const struct in6_addr *address)
{
    return (address->s6_addr[0] & 0xfe) == 0xfc;
}

static const struct in6_addr *snapshot_find(const struct dns_snapshot *snapshot, const char *name)
{
    for (unsigned int i = 0; i < snapshot->count; i++) {
        if (strcmp(snapshot->entries[i].name, name) == 0)
            return &snapshot->entries[i].address;
    }
    return NULL;
}

int dns_snapshot_take(struct dns_snapshot *snapshot)
{
    struct ifaddrs *addresses;

    snapshot->count = 0;
    if (getifaddrs(&addresses) < 0)
        return -1;
    for (const struct ifaddrs *item = addresses; item != NULL; item = item->ifa_next) {
        const struct sockaddr_in6 *ipv6 = (const struct sockaddr_in6 *)item->ifa_addr;

        if (item->ifa_addr == NULL || item->ifa_addr->sa_family != AF_INET6)
            continue;
        if (!dns_is_ula(&ipv6->sin6_addr) || snapshot_find(snapshot, item->ifa_name) != NULL)
            continue;
        if (snapshot->count == DNS_SNAPSHOT_MAX || strlen(item->ifa_name) >= IF_NAMESIZE)
            continue;
        strcpy(snapshot->entries[snapshot->count].name, item->ifa_name);
        snapshot->entries[snapshot->count].address = ipv6->sin6_addr;
        snapshot->count++;
    }
    freeifaddrs(addresses);
    return 0;
}

bool dns_bridge_master(const char *device, char *master)
{
    char path[sizeof(SYSFS_NETWORK_DIRECTORY) + IF_NAMESIZE + sizeof("/master")];
    char target[PATH_MAX];
    const char *base;
    ssize_t length;

    snprintf(path, sizeof(path), SYSFS_NETWORK_DIRECTORY "%s/master", device);
    length = readlink(path, target, sizeof(target) - 1);
    if (length <= 0)
        return false;
    target[length] = '\0';
    base = strrchr(target, '/');
    base = base == NULL ? target : base + 1;
    if (base[0] == '\0' || strlen(base) >= IF_NAMESIZE)
        return false;
    strcpy(master, base);
    return true;
}

bool dns_select(
    const struct dns_snapshot *snapshot,
    const char *device,
    const char *master,
    struct in6_addr *address,
    const char **source
)
{
    const struct in6_addr *found = snapshot_find(snapshot, device);

    *source = device;
    if (found == NULL && master[0] != '\0') {
        found = snapshot_find(snapshot, master);
        *source = master;
    }
    if (found == NULL)
        return false;
    *address = *found;
    return true;
}
