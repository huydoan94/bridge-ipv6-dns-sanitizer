#ifndef L2DNS6RW_NETLINK_H
#define L2DNS6RW_NETLINK_H

/* A non-blocking rtnetlink socket for link and IPv6 address changes. */
int netlink_open(void);

/* Reads every pending message; 1 when any arrived (or some were lost), 0 none, -1 error. */
int netlink_drain(int fd);

#endif
