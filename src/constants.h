#ifndef BRIDGE_IPV6_DNS_CONSTANTS_H
#define BRIDGE_IPV6_DNS_CONSTANTS_H

#include <limits.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>

#include <linux/if_ether.h>
#include <linux/netlink.h>

#ifndef BRIDGE_IPV6_DNS_SANITIZER_VERSION
#define BRIDGE_IPV6_DNS_SANITIZER_VERSION "unknown"
#endif

constexpr char PROGRAM_VERSION[] = BRIDGE_IPV6_DNS_SANITIZER_VERSION;

constexpr uint32_t QUEUE_MAXLEN = 1024U;
constexpr uint32_t COPY_RANGE = UINT16_MAX;
constexpr size_t NFQ_MAX_PAYLOAD = UINT16_MAX - NLA_HDRLEN;
constexpr int POLL_TIMEOUT_MS = 1000;
constexpr unsigned int DNS_REFRESH_SECONDS = 5U;
constexpr char DNS_CACHE_TEMPLATE[] = "/tmp/bridge-ipv6-dns-XXXXXX";
constexpr size_t NFQ_NETLINK_HEADROOM = 4096U;
constexpr size_t NFQ_RECV_BUFSIZE = COPY_RANGE + NFQ_NETLINK_HEADROOM;

constexpr unsigned int IPV6_WIRE_VERSION = 6U;
constexpr unsigned int IPV6_VERSION_FIELD_BITS = 4U;
constexpr uint8_t IPV6_ULA_PREFIX_MASK = 0xfeU;
constexpr uint8_t IPV6_ULA_PREFIX_VALUE = 0xfcU;
constexpr char IPV6_ALL_NODES[] = "ff02::1";
constexpr char IPV6_ALL_DHCP_AGENTS[] = "ff02::1:2";
constexpr uint16_t DHCPV6_SERVER_PORT = 547U;
constexpr uint16_t DHCPV6_CLIENT_PORT = 546U;
constexpr unsigned int CHECKSUM_WORD_BITS = sizeof(uint16_t) * CHAR_BIT;

constexpr char SYSFS_NETWORK_DIRECTORY[] = "/sys/class/net/";
constexpr char SYSFS_BRIDGE_MASTER_LINK[] = "/master";
constexpr size_t SYSFS_LINK_BUFSIZE = 256U;

constexpr uint16_t RA_NEUTRAL_ROUTER_LIFETIME = 0U;
constexpr uint8_t ND_OPTION_PVD = 21U;
constexpr uint16_t CHECKSUM_INVALID_XOR = 0x0001U;
constexpr size_t DHCPV6_TRANSACTION_ID_LEN = 3U;
constexpr size_t NDP_OPTION_LEN_UNIT_OCTETS = 8U;
constexpr size_t MAX_CONFIGURED_DNS_SERVERS = 10U;

constexpr size_t ADDR_LIST_BUFSIZE = 512U;
constexpr size_t MAC_TEXT_BUFSIZE = ETH_ALEN * sizeof("ff");
constexpr size_t CLIENT_ID_BUFSIZE = 384U;
constexpr size_t DETAIL_BUFSIZE = 1536U;
constexpr size_t ERROR_BUFSIZE = 256U;
constexpr size_t ENDPOINT_BUFSIZE = 256U;
constexpr size_t LOCAL_DNS_TEXT_BUFSIZE = INET6_ADDRSTRLEN + IF_NAMESIZE + sizeof("()");

#endif
