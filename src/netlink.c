#include "netlink.h"

#include <errno.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int netlink_open(void)
{
    struct sockaddr_nl address;
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, NETLINK_ROUTE);

    if (fd < 0)
        return -1;
    memset(&address, 0, sizeof(address));
    address.nl_family = AF_NETLINK;
    address.nl_groups = RTMGRP_LINK | RTMGRP_IPV6_IFADDR;
    if (bind(fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int netlink_drain(int fd)
{
    char buffer[8192];
    int changed = 0;

    for (;;) {
        const ssize_t length = recv(fd, buffer, sizeof(buffer), 0);

        if (length > 0) {
            changed = 1;
            continue;
        }
        if (length == 0 || errno == EAGAIN || errno == EWOULDBLOCK)
            return changed;
        if (errno == EINTR)
            continue;
        /* Messages were lost: treat it as a change and rescan. */
        if (errno == ENOBUFS)
            return 1;
        return -1;
    }
}
